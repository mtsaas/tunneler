// Informerprobe times how long a client-go informer takes to sync through a
// kubeconfig context, which is what k9s and similar tools wait for before
// they show anything.
//
//	go run ./hack/informerprobe CONTEXT
//	DISABLE_HTTP2=1 go run ./hack/informerprobe CONTEXT
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{CurrentContext: os.Args[1]}).ClientConfig()
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	factory := informers.NewSharedInformerFactory(kubernetes.NewForConfigOrDie(cfg), 0)
	informer := factory.Core().V1().Namespaces().Informer()
	start := time.Now()
	factory.Start(ctx.Done())
	if cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		fmt.Printf("synced after %.1fs with %d namespaces\n", time.Since(start).Seconds(), len(informer.GetStore().List()))
	} else {
		fmt.Printf("NOT synced after %.1fs; the store holds %d namespaces\n", time.Since(start).Seconds(), len(informer.GetStore().List()))
	}
}
