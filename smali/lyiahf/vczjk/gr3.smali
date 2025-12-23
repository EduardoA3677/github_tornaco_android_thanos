.class public final Llyiahf/vczjk/gr3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/cx2;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/sc9;

.field public final OooO0O0:Llyiahf/vczjk/sc9;

.field public final OooO0OO:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/sc9;Llyiahf/vczjk/sc9;Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/gr3;->OooO00o:Llyiahf/vczjk/sc9;

    iput-object p2, p0, Llyiahf/vczjk/gr3;->OooO0O0:Llyiahf/vczjk/sc9;

    iput-boolean p3, p0, Llyiahf/vczjk/gr3;->OooO0OO:Z

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/Object;Llyiahf/vczjk/hf6;)Llyiahf/vczjk/dx2;
    .locals 6

    check-cast p1, Landroid/net/Uri;

    invoke-virtual {p1}, Landroid/net/Uri;->getScheme()Ljava/lang/String;

    move-result-object v0

    const-string v1, "http"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p1}, Landroid/net/Uri;->getScheme()Ljava/lang/String;

    move-result-object v0

    const-string v1, "https"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    return-object p1

    :cond_1
    :goto_0
    new-instance v0, Llyiahf/vczjk/jr3;

    invoke-virtual {p1}, Landroid/net/Uri;->toString()Ljava/lang/String;

    move-result-object v1

    iget-object v3, p0, Llyiahf/vczjk/gr3;->OooO00o:Llyiahf/vczjk/sc9;

    iget-object v4, p0, Llyiahf/vczjk/gr3;->OooO0O0:Llyiahf/vczjk/sc9;

    iget-boolean v5, p0, Llyiahf/vczjk/gr3;->OooO0OO:Z

    move-object v2, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/jr3;-><init>(Ljava/lang/String;Llyiahf/vczjk/hf6;Llyiahf/vczjk/sc9;Llyiahf/vczjk/sc9;Z)V

    return-object v0
.end method
