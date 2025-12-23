.class public final Llyiahf/vczjk/m58;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/n58;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/n58;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/n58;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/m58;->this$0:Llyiahf/vczjk/n58;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/m58;->this$0:Llyiahf/vczjk/n58;

    iget-object v1, v0, Llyiahf/vczjk/n58;->OooOOO0:Llyiahf/vczjk/k68;

    iget-object v2, v0, Llyiahf/vczjk/n58;->OooOOOo:Ljava/lang/Object;

    if-eqz v2, :cond_0

    invoke-interface {v1, v0, v2}, Llyiahf/vczjk/k68;->OooO00o(Llyiahf/vczjk/n58;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0

    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Value should be initialized"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method
