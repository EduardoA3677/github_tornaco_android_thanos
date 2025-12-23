.class public final Llyiahf/vczjk/d96;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO:Z

.field public final OooO00o:Llyiahf/vczjk/ld9;

.field public final OooO0O0:Llyiahf/vczjk/sw7;

.field public final OooO0OO:Ljava/util/ArrayList;

.field public final OooO0Oo:Ljava/util/ArrayList;

.field public final OooO0o:Z

.field public final OooO0o0:Llyiahf/vczjk/ml9;

.field public final OooO0oO:Llyiahf/vczjk/rp3;

.field public final OooO0oo:Z

.field public final OooOO0:Llyiahf/vczjk/wp3;

.field public final OooOO0O:Llyiahf/vczjk/qp3;

.field public final OooOO0o:Llyiahf/vczjk/rp3;

.field public OooOOO:Ljavax/net/ssl/SSLSocketFactory;

.field public final OooOOO0:Ljavax/net/SocketFactory;

.field public OooOOOO:Ljavax/net/ssl/X509TrustManager;

.field public final OooOOOo:Ljava/util/List;

.field public OooOOo:Ljavax/net/ssl/HostnameVerifier;

.field public final OooOOo0:Ljava/util/List;

.field public final OooOOoo:Llyiahf/vczjk/yr0;

.field public final OooOo0:I

.field public OooOo00:Llyiahf/vczjk/zsa;

.field public final OooOo0O:I

.field public final OooOo0o:I


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/ld9;

    const/16 v1, 0xe

    invoke-direct {v0, v1}, Llyiahf/vczjk/ld9;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/d96;->OooO00o:Llyiahf/vczjk/ld9;

    new-instance v0, Llyiahf/vczjk/sw7;

    const/16 v1, 0xb

    invoke-direct {v0, v1}, Llyiahf/vczjk/sw7;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/d96;->OooO0O0:Llyiahf/vczjk/sw7;

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/d96;->OooO0OO:Ljava/util/ArrayList;

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/d96;->OooO0Oo:Ljava/util/ArrayList;

    new-instance v0, Llyiahf/vczjk/ml9;

    const/16 v1, 0xa

    invoke-direct {v0, v1}, Llyiahf/vczjk/ml9;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/d96;->OooO0o0:Llyiahf/vczjk/ml9;

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/d96;->OooO0o:Z

    sget-object v1, Llyiahf/vczjk/rp3;->OooOOO:Llyiahf/vczjk/rp3;

    iput-object v1, p0, Llyiahf/vczjk/d96;->OooO0oO:Llyiahf/vczjk/rp3;

    iput-boolean v0, p0, Llyiahf/vczjk/d96;->OooO0oo:Z

    iput-boolean v0, p0, Llyiahf/vczjk/d96;->OooO:Z

    sget-object v0, Llyiahf/vczjk/wp3;->OooOOOO:Llyiahf/vczjk/wp3;

    iput-object v0, p0, Llyiahf/vczjk/d96;->OooOO0:Llyiahf/vczjk/wp3;

    sget-object v0, Llyiahf/vczjk/qp3;->OooOOOo:Llyiahf/vczjk/qp3;

    iput-object v0, p0, Llyiahf/vczjk/d96;->OooOO0O:Llyiahf/vczjk/qp3;

    iput-object v1, p0, Llyiahf/vczjk/d96;->OooOO0o:Llyiahf/vczjk/rp3;

    invoke-static {}, Ljavax/net/SocketFactory;->getDefault()Ljavax/net/SocketFactory;

    move-result-object v0

    const-string v1, "getDefault()"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object v0, p0, Llyiahf/vczjk/d96;->OooOOO0:Ljavax/net/SocketFactory;

    sget-object v0, Llyiahf/vczjk/e96;->Oooo0o:Ljava/util/List;

    iput-object v0, p0, Llyiahf/vczjk/d96;->OooOOOo:Ljava/util/List;

    sget-object v0, Llyiahf/vczjk/e96;->Oooo0o0:Ljava/util/List;

    iput-object v0, p0, Llyiahf/vczjk/d96;->OooOOo0:Ljava/util/List;

    sget-object v0, Llyiahf/vczjk/z86;->OooO00o:Llyiahf/vczjk/z86;

    iput-object v0, p0, Llyiahf/vczjk/d96;->OooOOo:Ljavax/net/ssl/HostnameVerifier;

    sget-object v0, Llyiahf/vczjk/yr0;->OooO0OO:Llyiahf/vczjk/yr0;

    iput-object v0, p0, Llyiahf/vczjk/d96;->OooOOoo:Llyiahf/vczjk/yr0;

    const/16 v0, 0x2710

    iput v0, p0, Llyiahf/vczjk/d96;->OooOo0:I

    iput v0, p0, Llyiahf/vczjk/d96;->OooOo0O:I

    iput v0, p0, Llyiahf/vczjk/d96;->OooOo0o:I

    return-void
.end method
