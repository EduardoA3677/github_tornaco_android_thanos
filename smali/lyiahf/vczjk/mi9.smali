.class public final Llyiahf/vczjk/mi9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $editProcessor:Llyiahf/vczjk/xk2;

.field final synthetic $onValueChange:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $session:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xk2;Llyiahf/vczjk/kx4;Llyiahf/vczjk/hl7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mi9;->$editProcessor:Llyiahf/vczjk/xk2;

    iput-object p2, p0, Llyiahf/vczjk/mi9;->$onValueChange:Llyiahf/vczjk/oe3;

    iput-object p3, p0, Llyiahf/vczjk/mi9;->$session:Llyiahf/vczjk/hl7;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Ljava/util/List;

    iget-object v0, p0, Llyiahf/vczjk/mi9;->$editProcessor:Llyiahf/vczjk/xk2;

    iget-object v1, p0, Llyiahf/vczjk/mi9;->$onValueChange:Llyiahf/vczjk/oe3;

    iget-object v2, p0, Llyiahf/vczjk/mi9;->$session:Llyiahf/vczjk/hl7;

    iget-object v2, v2, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/yl9;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/xk2;->OooO00o(Ljava/util/List;)Llyiahf/vczjk/gl9;

    move-result-object p1

    if-eqz v2, :cond_0

    const/4 v0, 0x0

    invoke-virtual {v2, v0, p1}, Llyiahf/vczjk/yl9;->OooO00o(Llyiahf/vczjk/gl9;Llyiahf/vczjk/gl9;)V

    :cond_0
    invoke-interface {v1, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
