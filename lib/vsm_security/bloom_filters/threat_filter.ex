defmodule VsmSecurity.BloomFilters.ThreatFilter do
  @moduledoc """
  Probabilistic threat detection using Bloom filters.
  Provides fast, memory-efficient threat signature matching.
  """

  use GenServer
  
  require Logger

  @type t :: %__MODULE__{
    filter: :bloom.bloom(),
    size: integer(),
    hash_functions: integer(),
    false_positive_rate: float(),
    item_count: integer(),
    metadata: map()
  }

  defstruct [
    :filter,
    :size,
    :hash_functions,
    :false_positive_rate,
    :item_count,
    :metadata
  ]

  # Optimal parameters for different use cases
  @presets %{
    small: %{size: 10_000, hash_functions: 3, target_fpr: 0.01},
    medium: %{size: 100_000, hash_functions: 4, target_fpr: 0.001},
    large: %{size: 1_000_000, hash_functions: 5, target_fpr: 0.0001},
    extreme: %{size: 10_000_000, hash_functions: 7, target_fpr: 0.00001}
  }

  # Client API

  @doc """
  Creates a new threat filter with specified parameters.
  """
  def new(opts \\ []) do
    preset = Keyword.get(opts, :preset, :medium)
    params = Map.get(@presets, preset, @presets.medium)
    
    size = Keyword.get(opts, :size, params.size)
    hash_functions = Keyword.get(opts, :hash_functions, params.hash_functions)
    
    # Create the bloom filter
    # Note: In real implementation, we'd use a proper Bloom filter library
    # For now, we'll simulate with a simple implementation
    filter = create_bloom_filter(size, hash_functions)
    
    %__MODULE__{
      filter: filter,
      size: size,
      hash_functions: hash_functions,
      false_positive_rate: params.target_fpr,
      item_count: 0,
      metadata: %{
        created_at: DateTime.utc_now(),
        preset: preset
      }
    }
  end

  @doc """
  Adds a threat signature to the filter.
  """
  def add(%__MODULE__{} = filter, signature) when is_binary(signature) do
    hashes = generate_hashes(signature, filter.hash_functions, filter.size)
    
    updated_filter = Enum.reduce(hashes, filter.filter, fn hash, acc ->
      :array.set(hash, 1, acc)
    end)
    
    %{filter | 
      filter: updated_filter,
      item_count: filter.item_count + 1
    }
  end

  @doc """
  Checks if a signature might be in the filter.
  Returns true if possibly present (may be false positive),
  false if definitely not present.
  """
  def contains?(%__MODULE__{} = filter, signature) when is_binary(signature) do
    hashes = generate_hashes(signature, filter.hash_functions, filter.size)
    
    Enum.all?(hashes, fn hash ->
      :array.get(hash, filter.filter) == 1
    end)
  end

  @doc """
  Returns the current size (number of items) in the filter.
  """
  def size(%__MODULE__{} = filter), do: filter.item_count

  @doc """
  Calculates the current false positive probability.
  """
  def false_positive_probability(%__MODULE__{} = filter) do
    # Formula: (1 - e^(-k*n/m))^k
    # where k = hash functions, n = items, m = size
    k = filter.hash_functions
    n = filter.item_count
    m = filter.size
    
    :math.pow(1 - :math.exp(-k * n / m), k)
  end

  @doc """
  Merges two bloom filters (must have same parameters).
  """
  def merge(%__MODULE__{} = filter1, %__MODULE__{} = filter2) do
    if filter1.size != filter2.size or filter1.hash_functions != filter2.hash_functions do
      {:error, :incompatible_filters}
    else
      # Merge filters with bitwise OR
      merged_filter = merge_arrays(filter1.filter, filter2.filter, filter1.size)
      
      %{filter1 |
        filter: merged_filter,
        item_count: filter1.item_count + filter2.item_count  # Approximate
      }
    end
  end

  @doc """
  Creates a counting bloom filter for removable items.
  """
  def new_counting(opts \\ []) do
    preset = Keyword.get(opts, :preset, :medium)
    params = Map.get(@presets, preset, @presets.medium)
    
    size = Keyword.get(opts, :size, params.size)
    hash_functions = Keyword.get(opts, :hash_functions, params.hash_functions)
    
    # Counting filter uses integers instead of bits
    filter = :array.new(size, default: 0)
    
    %__MODULE__{
      filter: filter,
      size: size,
      hash_functions: hash_functions,
      false_positive_rate: params.target_fpr,
      item_count: 0,
      metadata: %{
        created_at: DateTime.utc_now(),
        preset: preset,
        type: :counting
      }
    }
  end

  @doc """
  Removes an item from a counting bloom filter.
  """
  def remove(%__MODULE__{metadata: %{type: :counting}} = filter, signature) do
    hashes = generate_hashes(signature, filter.hash_functions, filter.size)
    
    # Check if item exists before removing
    if contains?(filter, signature) do
      updated_filter = Enum.reduce(hashes, filter.filter, fn hash, acc ->
        current = :array.get(hash, acc)
        :array.set(hash, max(0, current - 1), acc)
      end)
      
      {:ok, %{filter | 
        filter: updated_filter,
        item_count: max(0, filter.item_count - 1)
      }}
    else
      {:error, :not_found}
    end
  end

  def remove(%__MODULE__{}, _signature) do
    {:error, :not_counting_filter}
  end

  @doc """
  Analyzes threat patterns in the filter.
  """
  def analyze_patterns(%__MODULE__{} = filter) do
    # Calculate bit density
    set_bits = count_set_bits(filter.filter, filter.size)
    density = set_bits / filter.size
    
    # Estimate unique items (uses approximation formula)
    estimated_items = estimate_unique_items(filter)
    
    # Calculate filter efficiency
    theoretical_optimal_bits = optimal_bit_count(filter.item_count, filter.false_positive_rate)
    efficiency = theoretical_optimal_bits / filter.size
    
    %{
      bit_density: density,
      estimated_unique_items: estimated_items,
      reported_items: filter.item_count,
      filter_efficiency: efficiency,
      current_fpr: false_positive_probability(filter),
      saturation: density > 0.5
    }
  end

  @doc """
  Exports filter to a compact binary format.
  """
  def export(%__MODULE__{} = filter) do
    data = %{
      size: filter.size,
      hash_functions: filter.hash_functions,
      item_count: filter.item_count,
      bits: serialize_array(filter.filter, filter.size)
    }
    
    :erlang.term_to_binary(data, [:compressed])
  end

  @doc """
  Imports filter from binary format.
  """
  def import(binary) when is_binary(binary) do
    data = :erlang.binary_to_term(binary)
    
    filter = deserialize_array(data.bits, data.size)
    
    %__MODULE__{
      filter: filter,
      size: data.size,
      hash_functions: data.hash_functions,
      false_positive_rate: 0.001,  # Default, will be recalculated
      item_count: data.item_count,
      metadata: %{
        imported_at: DateTime.utc_now()
      }
    }
  end

  # Private Functions

  defp create_bloom_filter(size, _hash_functions) do
    # Create array of bits (using 0/1 integers for simplicity)
    :array.new(size, default: 0)
  end

  defp generate_hashes(data, num_hashes, filter_size) do
    # Use different hash functions
    # In production, use proper hash functions like MurmurHash3
    base_hash = :erlang.phash2(data)
    
    Enum.map(0..(num_hashes - 1), fn i ->
      # Simple double hashing scheme: h(i) = h1(x) + i*h2(x)
      hash1 = :erlang.phash2({data, i})
      hash2 = :erlang.phash2({i, data})
      
      rem(hash1 + i * hash2, filter_size)
    end)
  end

  defp merge_arrays(array1, array2, size) do
    Enum.reduce(0..(size - 1), :array.new(size), fn i, acc ->
      val1 = :array.get(i, array1)
      val2 = :array.get(i, array2)
      
      # Bitwise OR for standard bloom filter
      :array.set(i, max(val1, val2), acc)
    end)
  end

  defp count_set_bits(array, size) do
    Enum.reduce(0..(size - 1), 0, fn i, acc ->
      if :array.get(i, array) > 0, do: acc + 1, else: acc
    end)
  end

  defp estimate_unique_items(filter) do
    # Using approximation: n ≈ -(m/k) * ln(1 - X/m)
    # where X is number of set bits
    set_bits = count_set_bits(filter.filter, filter.size)
    
    if set_bits == 0 do
      0
    else
      m = filter.size
      k = filter.hash_functions
      x = set_bits
      
      -1 * (m / k) * :math.log(1 - x / m)
      |> round()
    end
  end

  defp optimal_bit_count(items, target_fpr) do
    # Optimal size: m = -n * ln(p) / (ln(2)^2)
    # where n = items, p = target FPR
    -1 * items * :math.log(target_fpr) / :math.pow(:math.log(2), 2)
    |> round()
  end

  defp serialize_array(array, size) do
    # Convert array to bit string
    bits = Enum.map(0..(size - 1), fn i ->
      if :array.get(i, array) > 0, do: 1, else: 0
    end)
    
    # Pack bits into binary
    for <<bit::1 <- :erlang.list_to_binary(bits)>>, into: <<>> do
      <<bit::1>>
    end
  end

  defp deserialize_array(bits, size) do
    # Unpack bits from binary
    bit_list = for <<bit::1 <- bits>>, do: bit
    
    # Create array from bits
    {array, _} = Enum.reduce(bit_list, {:array.new(size), 0}, fn bit, {arr, idx} ->
      if idx < size do
        {:array.set(idx, bit, arr), idx + 1}
      else
        {arr, idx}
      end
    end)
    
    array
  end
end