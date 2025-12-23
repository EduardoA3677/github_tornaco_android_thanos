.class public final Llyiahf/vczjk/zk9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $density:Llyiahf/vczjk/f62;

.field final synthetic $magnifierSize$delegate:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/f62;Llyiahf/vczjk/qs5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/zk9;->$density:Llyiahf/vczjk/f62;

    iput-object p2, p0, Llyiahf/vczjk/zk9;->$magnifierSize$delegate:Llyiahf/vczjk/qs5;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/le3;

    sget-object v0, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    new-instance v1, Llyiahf/vczjk/xk9;

    invoke-direct {v1, p1}, Llyiahf/vczjk/xk9;-><init>(Llyiahf/vczjk/le3;)V

    new-instance p1, Llyiahf/vczjk/yk9;

    iget-object v2, p0, Llyiahf/vczjk/zk9;->$density:Llyiahf/vczjk/f62;

    iget-object v3, p0, Llyiahf/vczjk/zk9;->$magnifierSize$delegate:Llyiahf/vczjk/qs5;

    invoke-direct {p1, v2, v3}, Llyiahf/vczjk/yk9;-><init>(Llyiahf/vczjk/f62;Llyiahf/vczjk/qs5;)V

    invoke-static {}, Llyiahf/vczjk/x95;->OooO00o()Z

    move-result v2

    if-eqz v2, :cond_2

    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v3, 0x1c

    if-ne v2, v3, :cond_0

    sget-object v2, Llyiahf/vczjk/yg0;->OooOOOO:Llyiahf/vczjk/yg0;

    goto :goto_0

    :cond_0
    sget-object v2, Llyiahf/vczjk/yg0;->OooOOOo:Llyiahf/vczjk/yg0;

    :goto_0
    invoke-static {}, Llyiahf/vczjk/x95;->OooO00o()Z

    move-result v3

    if-eqz v3, :cond_1

    new-instance v0, Landroidx/compose/foundation/MagnifierElement;

    invoke-direct {v0, v1, p1, v2}, Landroidx/compose/foundation/MagnifierElement;-><init>(Llyiahf/vczjk/xk9;Llyiahf/vczjk/yk9;Llyiahf/vczjk/ix6;)V

    :cond_1
    return-object v0

    :cond_2
    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string v0, "Magnifier is only supported on API level 28 and higher."

    invoke-direct {p1, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
