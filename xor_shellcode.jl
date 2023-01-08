using ArgParse
using IterTools
import Base.⊻

function ⊻(x::Array{UInt8, 1}, y::Array{UInt8, 1})
    return map((i, j) -> i ⊻ j, x, y)
end

function xor_shellcode(code::String, key::String) :: Array{UInt8, 1}
    contains(key, "\\x") ? (key = hex2bytes(replace(key, "\\x"=>""))) : (println("[!] Key is not a hex sequence, assuming an ascii sequence"); key = [UInt8(Char(i)) for i in key])
    contains(code, "\\x") ? (code = hex2bytes(replace(code, "\\x"=>""))) : (println("[!] Shellcode is not a hex sequence, assuming an ascii sequence"); code = [UInt8(Char(i)) for i in code])
    @show key, code
    # This assumes that the key and message are passed as raw bytes and not their printable character / ascii / unicode form
#    base_c == 16 ? code = Array{UInt8, 1}([parse(UInt8, join(i), base = base_c) for i in partition(code, 2)]) : 
    println("\nLength: $(length(code))\n")
#    base_k == 16 ? (key = Array{UInt8, 1}([parse(UInt8, join(i), base = base_k) for i in partition(key, 2)])) : (key = Array{UInt8, 1}([parse(UInt8, join(i), base = base_k) for i in key]))
    if length(key) < length(code)
        key = append!(repeat(key, (length(code) ÷ length(key))), key[1 : length(code) % length(key)])
        length(key) == length(code) && println("Padded the key...\n")
    end
    return code ⊻ key
end

function parse_cli() :: Dict{String, Any}
    setting = ArgParseSettings(description = "Quick Script to XOR a shellcode/Char array with a provided key",
                                version = "0.01",
                                epilog = "Hey You, yes You, have a good day!",
                                add_version = true)
    @add_arg_table setting begin
        "-o", "--out","--ouput"
        help = "Write the output to a file"
        arg_type = String
        "-i", "--input"
        help = "Take the input from file instead of args"
        arg_type = String
        "-k", "--key"
        help = "Key to use for the encryption"
        arg_type = String
        "-m", "--message"
        help = "Shellcode to encrypt"
        arg_type = String
    end
    return parse_args(setting)
end
function init()
    Args = parse_cli()
    hexToStr = x -> join(Array{String, 1}([raw"\x" * string(i, base = 16, pad = 2) for i in x]))
    inpFile::Bool = false
    ptext::String = ""
    if Args["input"] !== nothing
        inpFile = true
        try
            f = open(Args["input"], "r")
            ptext = read(f, String)
        catch SystemError
            println("no such file exists in $(pwd())")
        finally
            close(f)
        end
    end
    if Args["out"] !== nothing
        try
            f = open("$(Args["out"])", "w")
            !(inpFile) && (ptext = Args["message"])
            write(f, arrayToStr(xor_shellcode(Args["key"], ptext)))
            println("\t[+] written to $(Args["out"])")
        catch SystemError
            println("error with writing to file $(Args["out"])")
        finally
            close(f)
        end
    else
#        @show Args
        println("\n[+] XORed Shellcode: \n $(hexToStr(xor_shellcode(Args["message"], Args["key"])))")
    end
end
init()