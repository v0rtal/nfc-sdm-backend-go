package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/v0rtal/nfc-sdm-backend-go/inventory"
)

//go:embed web/index.html
var indexHTML string
var indexPage = template.Must(template.New("index").Parse(indexHTML))

type directoryItem struct {
	Tag         inventory.Tag
	Information string
	Preview     string
}

func (b *backend) directory(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", 405)
		return
	}
	data := struct {
		Items                                     []directoryItem
		Single, Unavailable, HasPrevious, HasNext bool
		Previous, Next                            int
	}{Unavailable: b.store == nil, Single: strings.HasPrefix(r.URL.Path, "/items/")}
	if b.store != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		var tags []inventory.Tag
		if data.Single {
			uid := strings.TrimPrefix(r.URL.Path, "/items/")
			if !uidPattern.MatchString(uid) {
				http.NotFound(w, r)
				return
			}
			tag, err := b.store.Get(ctx, uid)
			if err != nil {
				dbError(w, err)
				return
			}
			tags = []inventory.Tag{tag}
		} else {
			page, err := strconv.Atoi(r.URL.Query().Get("page"))
			if err != nil || page < 1 {
				page = 1
			}
			if page > 100000 {
				http.Error(w, "Page number too large", 400)
				return
			}
			listed, err := b.store.List(ctx, 25, (page-1)*24)
			if err != nil {
				dbError(w, err)
				return
			}
			data.HasNext = len(listed) > 24
			if data.HasNext {
				listed = listed[:24]
			}
			data.HasPrevious = page > 1
			data.Previous = page - 1
			data.Next = page + 1
			tags = listed
		}
		for _, tag := range tags {
			item := directoryItem{Tag: tag}
			words := strings.Fields(tag.Description)
			if len(words) > 10 {
				item.Preview = strings.Join(words[:10], " ") + "…"
			} else {
				item.Preview = strings.Join(words, " ")
			}
			if len(tag.Attributes) > 0 && string(tag.Attributes) != "{}" {
				var formatted bytes.Buffer
				if json.Indent(&formatted, tag.Attributes, "", "  ") == nil {
					item.Information = formatted.String()
				}
			}
			data.Items = append(data.Items, item)
		}
	}
	var rendered bytes.Buffer
	if err := indexPage.Execute(&rendered, data); err != nil {
		http.Error(w, "Cannot display directory", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(rendered.Bytes())
}
