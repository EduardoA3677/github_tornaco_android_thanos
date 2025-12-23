.class public final Llyiahf/vczjk/isa;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $content:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic this$0:Llyiahf/vczjk/jsa;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jsa;Llyiahf/vczjk/ze3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/isa;->this$0:Llyiahf/vczjk/jsa;

    iput-object p2, p0, Llyiahf/vczjk/isa;->$content:Llyiahf/vczjk/ze3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/ba;

    iget-object v0, p0, Llyiahf/vczjk/isa;->this$0:Llyiahf/vczjk/jsa;

    iget-boolean v0, v0, Llyiahf/vczjk/jsa;->OooOOOO:Z

    if-nez v0, :cond_1

    iget-object p1, p1, Llyiahf/vczjk/ba;->OooO00o:Llyiahf/vczjk/uy4;

    invoke-interface {p1}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/isa;->this$0:Llyiahf/vczjk/jsa;

    iget-object v1, p0, Llyiahf/vczjk/isa;->$content:Llyiahf/vczjk/ze3;

    iput-object v1, v0, Llyiahf/vczjk/jsa;->OooOOo0:Llyiahf/vczjk/ze3;

    iget-object v1, v0, Llyiahf/vczjk/jsa;->OooOOOo:Llyiahf/vczjk/ky4;

    if-nez v1, :cond_0

    iput-object p1, v0, Llyiahf/vczjk/jsa;->OooOOOo:Llyiahf/vczjk/ky4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ky4;->OooO00o(Llyiahf/vczjk/ty4;)V

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/ky4;->OooO0O0()Llyiahf/vczjk/jy4;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/jy4;->OooOOOO:Llyiahf/vczjk/jy4;

    invoke-virtual {p1, v0}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    move-result p1

    if-ltz p1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/isa;->this$0:Llyiahf/vczjk/jsa;

    iget-object v0, p1, Llyiahf/vczjk/jsa;->OooOOO:Llyiahf/vczjk/sg1;

    new-instance v1, Llyiahf/vczjk/hsa;

    iget-object v2, p0, Llyiahf/vczjk/isa;->$content:Llyiahf/vczjk/ze3;

    invoke-direct {v1, p1, v2}, Llyiahf/vczjk/hsa;-><init>(Llyiahf/vczjk/jsa;Llyiahf/vczjk/ze3;)V

    new-instance p1, Llyiahf/vczjk/a91;

    const v2, -0x773f589e

    const/4 v3, 0x1

    invoke-direct {p1, v2, v1, v3}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    invoke-virtual {v0, p1}, Llyiahf/vczjk/sg1;->OooOO0(Llyiahf/vczjk/a91;)V

    :cond_1
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
