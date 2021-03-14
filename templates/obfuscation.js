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
	for(;iterations>0;iterations--){
		b64 = window.atob(b64);
	}
	buff = contentToBuffer(b64);
	var blob = new Blob([buff], {type: 'octet/stream'});
	return blob;
}


// For uploads
function encoder(blob,iterations){
	if(!iterations) {iterations = 1};
	var reader = new FileReader();
	var data;
	reader.onloadend = function() {
		var data = reader.result;
		for(;iterations>0;iterations--){
			data = window.btoa(data);
			// TODO: Perform POST request
		}
	}
	reader.readAsbinaryString(blob);
}

// For downloads
function decoder(fname){
	var xhttp = new XMLHttpRequest();
	xhttp.open("GET",fname,true);
	xhttp.onreadystatechange = function() {
		if(this.readyState == 4 && this.status == 200){
			var blob = decode64(this.responseText, 2);
			var a = document.createElement('a');
			var u = window.URL.createObjectURL(blob);
			document.body.appendChild(a);
			a.style = 'display:none';
			a.href = u;
			a.download = fname;
			a.click();
			window.URL.revokeObjectURL(u);
		}
	}
	xhttp.send();
}
