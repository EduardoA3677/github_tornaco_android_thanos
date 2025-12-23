.class public final Llyiahf/vczjk/nt8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $key:Llyiahf/vczjk/ht8;

.field final synthetic $state:Llyiahf/vczjk/mv2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/mv2;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/mv2;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/nt8;->$state:Llyiahf/vczjk/mv2;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/nt8;->$state:Llyiahf/vczjk/mv2;

    iget-object v0, v0, Llyiahf/vczjk/mv2;->OooO00o:Ljava/lang/Object;

    const/4 v1, 0x0

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/nt8;->$state:Llyiahf/vczjk/mv2;

    iget-object v0, v0, Llyiahf/vczjk/mv2;->OooO0O0:Ljava/util/ArrayList;

    new-instance v1, Llyiahf/vczjk/mt8;

    const/4 v2, 0x1

    invoke-direct {v1, v2}, Llyiahf/vczjk/rm4;-><init>(I)V

    invoke-static {v0, v1}, Llyiahf/vczjk/j21;->Ooooo0o(Ljava/util/List;Llyiahf/vczjk/oe3;)V

    iget-object v0, p0, Llyiahf/vczjk/nt8;->$state:Llyiahf/vczjk/mv2;

    iget-object v0, v0, Llyiahf/vczjk/mv2;->OooO0OO:Llyiahf/vczjk/aj7;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/aj7;->OooO0OO()V

    :cond_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
