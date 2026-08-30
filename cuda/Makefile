# Build the CUDA vanity kernel. sm_89 = Ada (RTX 40-series).
ARCH ?= sm_89
NVCC ?= nvcc
# FIELD32: eight 32-bit limbs instead of four 64-bit ones. NVIDIA emulates
# 64-bit integer multiply, and the modular reduction becomes a multiply by the
# small constant 977 rather than a full-width one. Worth +13.2%.
FIELD ?= -DFIELD32=1
CFLAGS = -O3 -arch=$(ARCH) -Xptxas -O3 $(FIELD)

all: gpu-vanity

gpu-vanity: vanity.cu field.cuh field32.cuh ec.cuh hash.cuh
	$(NVCC) $(CFLAGS) -o $@ vanity.cu

# The 64-bit limb build, kept as a second opinion on the field arithmetic.
gpu-vanity64: vanity.cu field.cuh ec.cuh hash.cuh
	$(NVCC) -O3 -arch=$(ARCH) -Xptxas -O3 -o $@ vanity.cu

clean:
	rm -f gpu-vanity gpu-vanity64 *.o
.PHONY: all clean
