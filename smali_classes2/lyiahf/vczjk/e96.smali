.class public final Llyiahf/vczjk/e96;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Cloneable;
.implements Llyiahf/vczjk/vn0;


# static fields
.field public static final Oooo0o:Ljava/util/List;

.field public static final Oooo0o0:Ljava/util/List;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/sw7;

.field public final OooOOO0:Llyiahf/vczjk/ld9;

.field public final OooOOOO:Ljava/util/List;

.field public final OooOOOo:Ljava/util/List;

.field public final OooOOo:Z

.field public final OooOOo0:Llyiahf/vczjk/ml9;

.field public final OooOOoo:Llyiahf/vczjk/rp3;

.field public final OooOo:Ljava/net/ProxySelector;

.field public final OooOo0:Z

.field public final OooOo00:Z

.field public final OooOo0O:Llyiahf/vczjk/wp3;

.field public final OooOo0o:Llyiahf/vczjk/qp3;

.field public final OooOoO:Ljavax/net/SocketFactory;

.field public final OooOoO0:Llyiahf/vczjk/rp3;

.field public final OooOoOO:Ljavax/net/ssl/SSLSocketFactory;

.field public final OooOoo:Ljava/util/List;

.field public final OooOoo0:Ljavax/net/ssl/X509TrustManager;

.field public final OooOooO:Ljava/util/List;

.field public final OooOooo:Ljavax/net/ssl/HostnameVerifier;

.field public final Oooo0:I

.field public final Oooo000:Llyiahf/vczjk/yr0;

.field public final Oooo00O:Llyiahf/vczjk/zsa;

.field public final Oooo00o:I

.field public final Oooo0O0:I

.field public final Oooo0OO:Llyiahf/vczjk/wg7;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/fe7;->OooOOOo:Llyiahf/vczjk/fe7;

    sget-object v1, Llyiahf/vczjk/fe7;->OooOOO:Llyiahf/vczjk/fe7;

    filled-new-array {v0, v1}, [Llyiahf/vczjk/fe7;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/kba;->OooOO0O([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/e96;->Oooo0o0:Ljava/util/List;

    sget-object v0, Llyiahf/vczjk/ni1;->OooO0o0:Llyiahf/vczjk/ni1;

    sget-object v1, Llyiahf/vczjk/ni1;->OooO0o:Llyiahf/vczjk/ni1;

    filled-new-array {v0, v1}, [Llyiahf/vczjk/ni1;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/kba;->OooOO0O([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/e96;->Oooo0o:Ljava/util/List;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/d96;

    invoke-direct {v0}, Llyiahf/vczjk/d96;-><init>()V

    invoke-direct {p0, v0}, Llyiahf/vczjk/e96;-><init>(Llyiahf/vczjk/d96;)V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/d96;)V
    .locals 4

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iget-object v0, p1, Llyiahf/vczjk/d96;->OooO00o:Llyiahf/vczjk/ld9;

    iput-object v0, p0, Llyiahf/vczjk/e96;->OooOOO0:Llyiahf/vczjk/ld9;

    iget-object v0, p1, Llyiahf/vczjk/d96;->OooO0O0:Llyiahf/vczjk/sw7;

    iput-object v0, p0, Llyiahf/vczjk/e96;->OooOOO:Llyiahf/vczjk/sw7;

    iget-object v0, p1, Llyiahf/vczjk/d96;->OooO0OO:Ljava/util/ArrayList;

    invoke-static {v0}, Llyiahf/vczjk/kba;->OooOo0O(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/e96;->OooOOOO:Ljava/util/List;

    iget-object v0, p1, Llyiahf/vczjk/d96;->OooO0Oo:Ljava/util/ArrayList;

    invoke-static {v0}, Llyiahf/vczjk/kba;->OooOo0O(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/e96;->OooOOOo:Ljava/util/List;

    iget-object v0, p1, Llyiahf/vczjk/d96;->OooO0o0:Llyiahf/vczjk/ml9;

    iput-object v0, p0, Llyiahf/vczjk/e96;->OooOOo0:Llyiahf/vczjk/ml9;

    iget-boolean v0, p1, Llyiahf/vczjk/d96;->OooO0o:Z

    iput-boolean v0, p0, Llyiahf/vczjk/e96;->OooOOo:Z

    iget-object v0, p1, Llyiahf/vczjk/d96;->OooO0oO:Llyiahf/vczjk/rp3;

    iput-object v0, p0, Llyiahf/vczjk/e96;->OooOOoo:Llyiahf/vczjk/rp3;

    iget-boolean v0, p1, Llyiahf/vczjk/d96;->OooO0oo:Z

    iput-boolean v0, p0, Llyiahf/vczjk/e96;->OooOo00:Z

    iget-boolean v0, p1, Llyiahf/vczjk/d96;->OooO:Z

    iput-boolean v0, p0, Llyiahf/vczjk/e96;->OooOo0:Z

    iget-object v0, p1, Llyiahf/vczjk/d96;->OooOO0:Llyiahf/vczjk/wp3;

    iput-object v0, p0, Llyiahf/vczjk/e96;->OooOo0O:Llyiahf/vczjk/wp3;

    iget-object v0, p1, Llyiahf/vczjk/d96;->OooOO0O:Llyiahf/vczjk/qp3;

    iput-object v0, p0, Llyiahf/vczjk/e96;->OooOo0o:Llyiahf/vczjk/qp3;

    invoke-static {}, Ljava/net/ProxySelector;->getDefault()Ljava/net/ProxySelector;

    move-result-object v0

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/q46;->OooO00o:Llyiahf/vczjk/q46;

    :cond_0
    iput-object v0, p0, Llyiahf/vczjk/e96;->OooOo:Ljava/net/ProxySelector;

    iget-object v0, p1, Llyiahf/vczjk/d96;->OooOO0o:Llyiahf/vczjk/rp3;

    iput-object v0, p0, Llyiahf/vczjk/e96;->OooOoO0:Llyiahf/vczjk/rp3;

    iget-object v0, p1, Llyiahf/vczjk/d96;->OooOOO0:Ljavax/net/SocketFactory;

    iput-object v0, p0, Llyiahf/vczjk/e96;->OooOoO:Ljavax/net/SocketFactory;

    iget-object v0, p1, Llyiahf/vczjk/d96;->OooOOOo:Ljava/util/List;

    iput-object v0, p0, Llyiahf/vczjk/e96;->OooOoo:Ljava/util/List;

    iget-object v1, p1, Llyiahf/vczjk/d96;->OooOOo0:Ljava/util/List;

    iput-object v1, p0, Llyiahf/vczjk/e96;->OooOooO:Ljava/util/List;

    iget-object v1, p1, Llyiahf/vczjk/d96;->OooOOo:Ljavax/net/ssl/HostnameVerifier;

    iput-object v1, p0, Llyiahf/vczjk/e96;->OooOooo:Ljavax/net/ssl/HostnameVerifier;

    iget v1, p1, Llyiahf/vczjk/d96;->OooOo0:I

    iput v1, p0, Llyiahf/vczjk/e96;->Oooo00o:I

    iget v1, p1, Llyiahf/vczjk/d96;->OooOo0O:I

    iput v1, p0, Llyiahf/vczjk/e96;->Oooo0:I

    iget v1, p1, Llyiahf/vczjk/d96;->OooOo0o:I

    iput v1, p0, Llyiahf/vczjk/e96;->Oooo0O0:I

    new-instance v1, Llyiahf/vczjk/wg7;

    invoke-direct {v1}, Llyiahf/vczjk/wg7;-><init>()V

    iput-object v1, p0, Llyiahf/vczjk/e96;->Oooo0OO:Llyiahf/vczjk/wg7;

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v2

    if-eqz v2, :cond_1

    goto/16 :goto_2

    :cond_1
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_6

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ni1;

    iget-boolean v2, v2, Llyiahf/vczjk/ni1;->OooO00o:Z

    if-eqz v2, :cond_2

    iget-object v0, p1, Llyiahf/vczjk/d96;->OooOOO:Ljavax/net/ssl/SSLSocketFactory;

    if-eqz v0, :cond_4

    iput-object v0, p0, Llyiahf/vczjk/e96;->OooOoOO:Ljavax/net/ssl/SSLSocketFactory;

    iget-object v0, p1, Llyiahf/vczjk/d96;->OooOo00:Llyiahf/vczjk/zsa;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iput-object v0, p0, Llyiahf/vczjk/e96;->Oooo00O:Llyiahf/vczjk/zsa;

    iget-object v2, p1, Llyiahf/vczjk/d96;->OooOOOO:Ljavax/net/ssl/X509TrustManager;

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iput-object v2, p0, Llyiahf/vczjk/e96;->OooOoo0:Ljavax/net/ssl/X509TrustManager;

    iget-object p1, p1, Llyiahf/vczjk/d96;->OooOOoo:Llyiahf/vczjk/yr0;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, p1, Llyiahf/vczjk/yr0;->OooO0O0:Llyiahf/vczjk/zsa;

    invoke-static {v2, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_3

    goto :goto_0

    :cond_3
    new-instance v2, Llyiahf/vczjk/yr0;

    iget-object p1, p1, Llyiahf/vczjk/yr0;->OooO00o:Ljava/util/Set;

    invoke-direct {v2, p1, v0}, Llyiahf/vczjk/yr0;-><init>(Ljava/util/Set;Llyiahf/vczjk/zsa;)V

    move-object p1, v2

    :goto_0
    iput-object p1, p0, Llyiahf/vczjk/e96;->Oooo000:Llyiahf/vczjk/yr0;

    goto :goto_3

    :cond_4
    sget-object v0, Llyiahf/vczjk/yw6;->OooO00o:Llyiahf/vczjk/yw6;

    sget-object v0, Llyiahf/vczjk/yw6;->OooO00o:Llyiahf/vczjk/yw6;

    invoke-virtual {v0}, Llyiahf/vczjk/yw6;->OooOOO0()Ljavax/net/ssl/X509TrustManager;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/e96;->OooOoo0:Ljavax/net/ssl/X509TrustManager;

    sget-object v2, Llyiahf/vczjk/yw6;->OooO00o:Llyiahf/vczjk/yw6;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/yw6;->OooOO0o(Ljavax/net/ssl/X509TrustManager;)Ljavax/net/ssl/SSLSocketFactory;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/e96;->OooOoOO:Ljavax/net/ssl/SSLSocketFactory;

    sget-object v2, Llyiahf/vczjk/yw6;->OooO00o:Llyiahf/vczjk/yw6;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/yw6;->OooO0O0(Ljavax/net/ssl/X509TrustManager;)Llyiahf/vczjk/zsa;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/e96;->Oooo00O:Llyiahf/vczjk/zsa;

    iget-object p1, p1, Llyiahf/vczjk/d96;->OooOOoo:Llyiahf/vczjk/yr0;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, p1, Llyiahf/vczjk/yr0;->OooO0O0:Llyiahf/vczjk/zsa;

    invoke-static {v2, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_5

    goto :goto_1

    :cond_5
    new-instance v2, Llyiahf/vczjk/yr0;

    iget-object p1, p1, Llyiahf/vczjk/yr0;->OooO00o:Ljava/util/Set;

    invoke-direct {v2, p1, v0}, Llyiahf/vczjk/yr0;-><init>(Ljava/util/Set;Llyiahf/vczjk/zsa;)V

    move-object p1, v2

    :goto_1
    iput-object p1, p0, Llyiahf/vczjk/e96;->Oooo000:Llyiahf/vczjk/yr0;

    goto :goto_3

    :cond_6
    :goto_2
    iput-object v1, p0, Llyiahf/vczjk/e96;->OooOoOO:Ljavax/net/ssl/SSLSocketFactory;

    iput-object v1, p0, Llyiahf/vczjk/e96;->Oooo00O:Llyiahf/vczjk/zsa;

    iput-object v1, p0, Llyiahf/vczjk/e96;->OooOoo0:Ljavax/net/ssl/X509TrustManager;

    sget-object p1, Llyiahf/vczjk/yr0;->OooO0OO:Llyiahf/vczjk/yr0;

    iput-object p1, p0, Llyiahf/vczjk/e96;->Oooo000:Llyiahf/vczjk/yr0;

    :goto_3
    iget-object p1, p0, Llyiahf/vczjk/e96;->OooOOOO:Ljava/util/List;

    const-string v0, "null cannot be cast to non-null type kotlin.collections.List<okhttp3.Interceptor?>"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1, v1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_12

    iget-object p1, p0, Llyiahf/vczjk/e96;->OooOOOo:Ljava/util/List;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1, v1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_11

    iget-object p1, p0, Llyiahf/vczjk/e96;->OooOoo0:Ljavax/net/ssl/X509TrustManager;

    iget-object v0, p0, Llyiahf/vczjk/e96;->Oooo00O:Llyiahf/vczjk/zsa;

    iget-object v1, p0, Llyiahf/vczjk/e96;->OooOoOO:Ljavax/net/ssl/SSLSocketFactory;

    iget-object v2, p0, Llyiahf/vczjk/e96;->OooOoo:Ljava/util/List;

    if-eqz v2, :cond_7

    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_7

    goto :goto_4

    :cond_7
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_8
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_c

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ni1;

    iget-boolean v3, v3, Llyiahf/vczjk/ni1;->OooO00o:Z

    if-eqz v3, :cond_8

    if-eqz v1, :cond_b

    if-eqz v0, :cond_a

    if-eqz p1, :cond_9

    goto :goto_5

    :cond_9
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "x509TrustManager == null"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_a
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "certificateChainCleaner == null"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_b
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "sslSocketFactory == null"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_c
    :goto_4
    const-string v2, "Check failed."

    if-nez v1, :cond_10

    if-nez v0, :cond_f

    if-nez p1, :cond_e

    iget-object p1, p0, Llyiahf/vczjk/e96;->Oooo000:Llyiahf/vczjk/yr0;

    sget-object v0, Llyiahf/vczjk/yr0;->OooO0OO:Llyiahf/vczjk/yr0;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_d

    :goto_5
    return-void

    :cond_d
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_e
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_f
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_10
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_11
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Null network interceptor: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_12
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Null interceptor: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method


# virtual methods
.method public final clone()Ljava/lang/Object;
    .locals 1

    invoke-super {p0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method
