.class public Llyiahf/vczjk/f;
.super Llyiahf/vczjk/sy5;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Llyiahf/vczjk/sy5;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0017\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001:\u0001\u0002\u00a8\u0006\u0003"
    }
    d2 = {
        "Llyiahf/vczjk/f;",
        "Llyiahf/vczjk/sy5;",
        "Llyiahf/vczjk/e;",
        "navigation-runtime_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation

.annotation runtime Llyiahf/vczjk/ry5;
    value = "activity"
.end annotation


# instance fields
.field public final OooO0OO:Landroid/app/Activity;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 2

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/o0OOooO0;

    const/4 v1, 0x3

    invoke-direct {v0, v1}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    invoke-static {p1, v0}, Llyiahf/vczjk/ag8;->Oooo0OO(Ljava/lang/Object;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/wf8;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/wf8;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Landroid/content/Context;

    instance-of v1, v1, Landroid/app/Activity;

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_0
    check-cast v0, Landroid/app/Activity;

    iput-object v0, p0, Llyiahf/vczjk/f;->OooO0OO:Landroid/app/Activity;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/av5;
    .locals 1

    new-instance v0, Llyiahf/vczjk/e;

    invoke-direct {v0, p0}, Llyiahf/vczjk/av5;-><init>(Llyiahf/vczjk/sy5;)V

    return-object v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/av5;)Llyiahf/vczjk/av5;
    .locals 2

    check-cast p1, Llyiahf/vczjk/e;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Destination "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object p1, p1, Llyiahf/vczjk/av5;->OooOOO:Llyiahf/vczjk/j1;

    iget p1, p1, Llyiahf/vczjk/j1;->OooO00o:I

    const-string v1, " does not have an Intent set."

    invoke-static {v0, p1, v1}, Llyiahf/vczjk/u81;->OooOOOO(Ljava/lang/StringBuilder;ILjava/lang/String;)Ljava/lang/String;

    move-result-object p1

    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final OooO0o()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f;->OooO0OO:Landroid/app/Activity;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroid/app/Activity;->finish()V

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method
