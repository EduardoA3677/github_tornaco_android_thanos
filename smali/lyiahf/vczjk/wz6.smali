.class public final Llyiahf/vczjk/wz6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/zz6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zz6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/wz6;->this$0:Llyiahf/vczjk/zz6;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/wz6;->this$0:Llyiahf/vczjk/zz6;

    invoke-static {v0}, Llyiahf/vczjk/zz6;->OooO(Llyiahf/vczjk/zz6;)Llyiahf/vczjk/xn4;

    move-result-object v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-interface {v0}, Llyiahf/vczjk/xn4;->OooOO0o()Z

    move-result v2

    if-eqz v2, :cond_0

    goto :goto_0

    :cond_0
    move-object v0, v1

    :goto_0
    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/wz6;->this$0:Llyiahf/vczjk/zz6;

    invoke-virtual {v0}, Llyiahf/vczjk/zz6;->getPopupContentSize-bOM6tXw()Llyiahf/vczjk/b24;

    move-result-object v0

    if-eqz v0, :cond_1

    const/4 v0, 0x1

    goto :goto_1

    :cond_1
    const/4 v0, 0x0

    :goto_1
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    return-object v0
.end method
