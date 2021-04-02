var interval;
var reloadFlag = false;
var encodeUploads = true;
var encodeDownloads = true;
var decodeDownloads = true;
var displayB64 = false;

function reloadWait () {
    interval = setInterval(function(){
        if(reloadFlag){
            reloadFlag=false;
            loadFiles();
        }
    })
}
reloadWait();

function toggleEncodeUploads(){
    encodeUploads=!encodeUploads;
    console.log('encodeUploads: '+encodeUploads);
    var e = document.getElementsByTagName("form")[0];
}

function toggleEncodeDownloads(){
    encodeDownloads=!encodeDownloads;
    console.log('encodeDownloads: '+encodeDownloads);

    if(!encodeDownloads && decodeDownloads){
        console.log('Resetting decode downloads.')
        toggleDecodeDownloads();
        var e = document.getElementsByName("toggleDecodeCheckbox")[0];
        e.checked=false;
    }

}

function toggleDecodeDownloads(){
    decodeDownloads=!decodeDownloads;
    console.log('decodeDownloads: '+decodeDownloads);
}

function toggleDisplayB64(){
    displayB64=!displayB64;
    console.log('displayB64: '+displayB64);
}

function contentToBuffer(b64){
	var len = b64.length;
	bytes = new Uint8Array(len);
	for(var i=0; i<len; i++){
		bytes[i] = b64.charCodeAt(i);
	}
	return bytes.buffer;
}

function decode64(b64,iterations){
	if(!iterations) {iterations = 1};
    console.log('Decoding the file.',iterations);
	for(;iterations>0;iterations--){
		b64 = window.atob(b64);
	}
	buff = contentToBuffer(b64);
	var blob = new Blob([buff], {type: 'octet/stream'});
	return blob;
}

// For uploads
function encoder(iterations){
	var form = document.getElementsByName("form");
	var submit = document.getElementsByName("submit");
	var input = document.querySelector('input[type="file"]');
	var file = input.files[0];
	if(!iterations) {iterations = 1};
	var reader = new FileReader();
	var data;
	reader.onloadend = function() {
        console.log('Upload initiated.');

		// Create new form data
		var formData = new FormData();

        if(encodeUploads){
    		// Process the file upload
            console.log('Encoding file.');
	    	var data = reader.result;
		    for(;iterations>0;iterations--){
    			data = window.btoa(data);
	    	}
		    formData.append("file",
                new Blob([data],{type: "text/base64"}), file.name);
            console.log('File encoded. Preparing to submit XHTTP POST request.');
        } else {
            formData.append("file", file);
        }

		// Make the HTTP request
		var xhttp = new XMLHttpRequest();
        xhttp.timeout=30000;
		xhttp.open("POST", window.location.pathname+'?e='+encodeUploads, true);
        xhttp.onreadystatechange = function() {
            if(this.readyState == 4 && this.status == 200){
                console.log('Upload appears to have succeeded');
                reloadFlag=true;
            } else {
                console.log('Upload appears to have failed.');
            }
        }
		xhttp.send(formData);
	}
	reader.readAsBinaryString(file);
    return false;
}

// For downloads
function downloader(fname){

    if(!encodeDownloads){

        console.log('Using generic download for '+fname);
        window.open(fname+"?=false", "_top");

    } else if(encodeDownloads && displayB64){

        console.log('Displaying B64 encoded variant for '+fname);
        genericDownload(fname, true, false);

    } else {

	    var xhttp = new XMLHttpRequest();
        var uri = fname+'?e='+encodeDownloads;
        console.log('Requesting download URI: '+uri)
    	xhttp.open("GET",uri,true);
        xhttp.timeout=30000;
    	xhttp.onreadystatechange = function() {
    		if(this.readyState == 4 && this.status == 200){
    			var blob;
                if(decodeDownloads){
                    console.log('Decoding downloaded file.');
                    blob = decode64(this.responseText, 2);
                } else {
                    console.log(
                        'Converting the file to a blob to force the download.');
                    blob = new Blob([this.responseText], {type:'text/base64'});
                }
    			var a = document.createElement('a');
    			var u = window.URL.createObjectURL(blob);
    			document.body.appendChild(a);
    			a.style = 'display:none';
    			a.href = u;
    			a.download = fname;
                console.log('Forcing the download');
    			a.click();
    			window.URL.revokeObjectURL(u);
    		}
    	}
    	xhttp.send();

     }
}

function genericDownload(fname,encode,tabbed){

    if(encode==undefined){
        encode=false;
    } else if(encode){
        encode=true;
    }

    if(tabbed){
        console.log("Opening B64 encoded file in tab");
        window.open(fname+"?e="+encode,'_blank');
    } else {
        console.log("Downloading file directly");
        window.open(fname+"?e="+encode, "_top");
    }

}

function loadFiles(){
    console.log("Requesting file listing.");
    var xhttp = new XMLHttpRequest();
    xhttp.open("GET",window.location.pathname+"SHTTPSSgetFiles",true);
    xhttp.onreadystatechange = function() {
        if(this.readyState == 4 && this.status == 200){
            console.log("Injecting file listing");
            var e = document.getElementById("listing");
            e.innerHTML = this.responseText;
        }
    }
    xhttp.send()
}

window.onload = loadFiles;
