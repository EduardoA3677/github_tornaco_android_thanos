.class public final Llyiahf/vczjk/nd;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $imeOptions:Llyiahf/vczjk/wv3;

.field final synthetic $onEditCommand:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $onImeActionPerformed:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $value:Llyiahf/vczjk/gl9;

.field final synthetic this$0:Llyiahf/vczjk/td;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gl9;Llyiahf/vczjk/td;Llyiahf/vczjk/wv3;Llyiahf/vczjk/mi9;Llyiahf/vczjk/jx4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/nd;->$value:Llyiahf/vczjk/gl9;

    iput-object p2, p0, Llyiahf/vczjk/nd;->this$0:Llyiahf/vczjk/td;

    iput-object p3, p0, Llyiahf/vczjk/nd;->$imeOptions:Llyiahf/vczjk/wv3;

    iput-object p4, p0, Llyiahf/vczjk/nd;->$onEditCommand:Llyiahf/vczjk/oe3;

    iput-object p5, p0, Llyiahf/vczjk/nd;->$onImeActionPerformed:Llyiahf/vczjk/oe3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    check-cast p1, Llyiahf/vczjk/nx4;

    iget-object v0, p0, Llyiahf/vczjk/nd;->$value:Llyiahf/vczjk/gl9;

    iget-object v1, p0, Llyiahf/vczjk/nd;->this$0:Llyiahf/vczjk/td;

    iget-object v1, v1, Llyiahf/vczjk/fx4;->OooO00o:Llyiahf/vczjk/cx4;

    iget-object v2, p0, Llyiahf/vczjk/nd;->$imeOptions:Llyiahf/vczjk/wv3;

    iget-object v3, p0, Llyiahf/vczjk/nd;->$onEditCommand:Llyiahf/vczjk/oe3;

    iget-object v4, p0, Llyiahf/vczjk/nd;->$onImeActionPerformed:Llyiahf/vczjk/oe3;

    iput-object v0, p1, Llyiahf/vczjk/nx4;->OooO0oo:Llyiahf/vczjk/gl9;

    iput-object v2, p1, Llyiahf/vczjk/nx4;->OooO:Llyiahf/vczjk/wv3;

    iput-object v3, p1, Llyiahf/vczjk/nx4;->OooO0OO:Llyiahf/vczjk/oe3;

    iput-object v4, p1, Llyiahf/vczjk/nx4;->OooO0Oo:Llyiahf/vczjk/oe3;

    const/4 v0, 0x0

    if-eqz v1, :cond_0

    iget-object v2, v1, Llyiahf/vczjk/cx4;->OooOoo0:Llyiahf/vczjk/lx4;

    goto :goto_0

    :cond_0
    move-object v2, v0

    :goto_0
    iput-object v2, p1, Llyiahf/vczjk/nx4;->OooO0o0:Llyiahf/vczjk/lx4;

    if-eqz v1, :cond_1

    iget-object v2, v1, Llyiahf/vczjk/cx4;->OooOoo:Llyiahf/vczjk/mk9;

    goto :goto_1

    :cond_1
    move-object v2, v0

    :goto_1
    iput-object v2, p1, Llyiahf/vczjk/nx4;->OooO0o:Llyiahf/vczjk/mk9;

    if-eqz v1, :cond_2

    sget-object v0, Llyiahf/vczjk/ch1;->OooOOoo:Llyiahf/vczjk/l39;

    invoke-static {v1, v0}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/gga;

    :cond_2
    iput-object v0, p1, Llyiahf/vczjk/nx4;->OooO0oO:Llyiahf/vczjk/gga;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
