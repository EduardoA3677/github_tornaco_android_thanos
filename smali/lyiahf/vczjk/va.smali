.class public final Llyiahf/vczjk/va;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/xa;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xa;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/va;->this$0:Llyiahf/vczjk/xa;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/xr1;

    new-instance v0, Llyiahf/vczjk/af;

    iget-object v1, p0, Llyiahf/vczjk/va;->this$0:Llyiahf/vczjk/xa;

    invoke-virtual {v1}, Llyiahf/vczjk/xa;->getTextInputService()Llyiahf/vczjk/tl9;

    move-result-object v2

    invoke-direct {v0, v1, v2, p1}, Llyiahf/vczjk/af;-><init>(Landroid/view/View;Llyiahf/vczjk/tl9;Llyiahf/vczjk/xr1;)V

    return-object v0
.end method
