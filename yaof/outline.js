document.addEventListener("DOMContentLoaded", function() {
    // ����Ŀ¼�б�
    var outline = document.createElement("ul");
    outline.setAttribute("id", "outline-list");
    outline.style.cssText = "border: 1px solid #ccc;";
    document.body.insertBefore(outline, document.body.childNodes[0]);
    // ��ȡ���б���
    var headers = document.querySelectorAll('h1,h2,h3,h4,h5,h6');
    for (var i = 0; i < headers.length; i++) {
        var header = headers[i];
        var hash = _hashCode(header.textContent);
        // MarkdownPad2�޷�Ϊ����header��ȷ����id����������һ��
        header.setAttribute("id", header.tagName + hash);
        // �ҳ�����H����Ϊ����ǰ�ÿո�׼��
        var prefix = parseInt(header.tagName.replace('H', ''), 10);
        outline.appendChild(document.createElement("li"));
        var a = document.createElement("a");
        // ΪĿ¼����������
        a.setAttribute("href", "#" + header.tagName + hash)
        // Ŀ¼���ı�ǰ����ö�Ӧ�Ŀո�
        a.innerHTML = new Array(prefix * 4).join('&nbsp;') + header.textContent;
        outline.lastChild.appendChild(a);
    }
 
});
 
// ����Java��hash���ɷ�ʽ��Ϊһ����������һ�λ��������ظ�������
function _hashCode(txt) {
     var hash = 0;
     if (txt.length == 0) return hash;
     for (i = 0; i < txt.length; i++) {
          char = txt.charCodeAt(i);
          hash = ((hash<<5)-hash)+char;
          hash = hash & hash; // Convert to 32bit integer
     }
     return hash;
}
 