.class public final Llyiahf/vczjk/vm6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $scope:Llyiahf/vczjk/v98;

.field final synthetic this$0:Llyiahf/vczjk/wm6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wm6;Llyiahf/vczjk/xa8;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vm6;->this$0:Llyiahf/vczjk/wm6;

    iput-object p2, p0, Llyiahf/vczjk/vm6;->$scope:Llyiahf/vczjk/v98;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/vm6;->this$0:Llyiahf/vczjk/wm6;

    iget-object v0, v0, Llyiahf/vczjk/wm6;->OooO0O0:Llyiahf/vczjk/lm6;

    invoke-virtual {v0}, Llyiahf/vczjk/lm6;->OooOOO()I

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/vm6;->this$0:Llyiahf/vczjk/wm6;

    iget-object v0, v0, Llyiahf/vczjk/wm6;->OooO0O0:Llyiahf/vczjk/lm6;

    invoke-virtual {v0}, Llyiahf/vczjk/lm6;->OooOOO()I

    move-result v0

    int-to-float v0, v0

    div-float/2addr p1, v0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    invoke-static {p1}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/vm6;->this$0:Llyiahf/vczjk/wm6;

    iget-object v0, v0, Llyiahf/vczjk/wm6;->OooO0O0:Llyiahf/vczjk/lm6;

    invoke-virtual {v0}, Llyiahf/vczjk/lm6;->OooOO0()I

    move-result v0

    add-int/2addr v0, p1

    iget-object p1, p0, Llyiahf/vczjk/vm6;->this$0:Llyiahf/vczjk/wm6;

    iget-object p1, p1, Llyiahf/vczjk/wm6;->OooO0O0:Llyiahf/vczjk/lm6;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/lm6;->OooO(I)I

    move-result v0

    iget-object p1, p1, Llyiahf/vczjk/lm6;->OooOOoo:Llyiahf/vczjk/qr5;

    check-cast p1, Llyiahf/vczjk/bw8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/bw8;->OooOo00(I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
