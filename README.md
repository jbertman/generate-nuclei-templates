## Usage

```
Usage of ./build/generate-nuclei-templates:
  -clone-path string
        Path to clone Wappalyzer repository (default "./wappalyzer")
  -debug
        Set log level to debug
  -force
        Force re-clone of Wappalyzer repository
  -merge-nuclei
        Download and merge non-overlapping matchers from nuclei's tech-detect.yaml
```

## Example

```
./build/generate-nuclei-templates -merge-nuclei
```
