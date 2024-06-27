package node

import (
	"log"

	"github.com/gin-gonic/gin"
)

func (n *Node) NotFoundHandler(c *gin.Context) {
	clientIp := c.ClientIP()
	log.Printf("[%s] %s", clientIp, c.Request.URL.Path)

	// b := bytes.NewBuffer(make([]byte, 0))
	// bw := bufio.NewWriter(b)
	// tpl := template.Must(template.New("tplName").Parse(tmpl.Notfound))
	// tpl.Execute(bw, nil)
	// bw.Flush()

	c.HTML(200, "notfound.html", nil)
}
