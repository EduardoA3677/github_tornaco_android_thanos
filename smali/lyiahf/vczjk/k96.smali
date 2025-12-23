.class public final Llyiahf/vczjk/k96;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/m96;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/m96;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/m96;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/k96;->this$0:Llyiahf/vczjk/m96;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/k96;->this$0:Llyiahf/vczjk/m96;

    iget-object v0, v0, Llyiahf/vczjk/m96;->OooO0Oo:Llyiahf/vczjk/rm4;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/zp6;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0}, Llyiahf/vczjk/OooOO0;->OooO00o(Llyiahf/vczjk/zp6;)I

    move-result v1

    const/4 v2, -0x1

    const/4 v3, 0x1

    if-eq v1, v2, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/k96;->this$0:Llyiahf/vczjk/m96;

    if-eqz v1, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/zp6;->OooOOO0:Llyiahf/vczjk/jm0;

    invoke-virtual {v0}, Llyiahf/vczjk/jm0;->OooOOoo()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0, v3}, Llyiahf/vczjk/xj0;->OooOOOo(Ljava/lang/String;Z)Llyiahf/vczjk/zp6;

    move-result-object v0

    return-object v0

    :cond_1
    new-instance v1, Ljava/lang/StringBuilder;

    const-string v3, "OkioStorage requires absolute paths, but did not get an absolute path from producePath = "

    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v2, v2, Llyiahf/vczjk/m96;->OooO0Oo:Llyiahf/vczjk/rm4;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, ", instead got "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/IllegalStateException;

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1
.end method
