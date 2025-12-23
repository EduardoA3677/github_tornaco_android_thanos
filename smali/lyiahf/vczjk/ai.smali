.class public final Llyiahf/vczjk/ai;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $block:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $clampingNeeded:Llyiahf/vczjk/dl7;

.field final synthetic $endState:Llyiahf/vczjk/xl;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/xl;"
        }
    .end annotation
.end field

.field final synthetic this$0:Llyiahf/vczjk/gi;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/gi;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gi;Llyiahf/vczjk/xl;Llyiahf/vczjk/oe3;Llyiahf/vczjk/dl7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ai;->this$0:Llyiahf/vczjk/gi;

    iput-object p2, p0, Llyiahf/vczjk/ai;->$endState:Llyiahf/vczjk/xl;

    iput-object p3, p0, Llyiahf/vczjk/ai;->$block:Llyiahf/vczjk/oe3;

    iput-object p4, p0, Llyiahf/vczjk/ai;->$clampingNeeded:Llyiahf/vczjk/dl7;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/fl;

    iget-object v0, p0, Llyiahf/vczjk/ai;->this$0:Llyiahf/vczjk/gi;

    iget-object v0, v0, Llyiahf/vczjk/gi;->OooO0OO:Llyiahf/vczjk/xl;

    invoke-static {p1, v0}, Llyiahf/vczjk/vc6;->OoooO0O(Llyiahf/vczjk/fl;Llyiahf/vczjk/xl;)V

    iget-object v0, p0, Llyiahf/vczjk/ai;->this$0:Llyiahf/vczjk/gi;

    iget-object v1, p1, Llyiahf/vczjk/fl;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/gi;->OooO0OO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v1

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/ai;->this$0:Llyiahf/vczjk/gi;

    iget-object v1, v1, Llyiahf/vczjk/gi;->OooO0OO:Llyiahf/vczjk/xl;

    iget-object v1, v1, Llyiahf/vczjk/xl;->OooOOO:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object v1, p0, Llyiahf/vczjk/ai;->$endState:Llyiahf/vczjk/xl;

    iget-object v1, v1, Llyiahf/vczjk/xl;->OooOOO:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/ai;->$block:Llyiahf/vczjk/oe3;

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/ai;->this$0:Llyiahf/vczjk/gi;

    invoke-interface {v0, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/fl;->OooO00o()V

    iget-object p1, p0, Llyiahf/vczjk/ai;->$clampingNeeded:Llyiahf/vczjk/dl7;

    const/4 v0, 0x1

    iput-boolean v0, p1, Llyiahf/vczjk/dl7;->element:Z

    goto :goto_0

    :cond_1
    iget-object p1, p0, Llyiahf/vczjk/ai;->$block:Llyiahf/vczjk/oe3;

    if-eqz p1, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/ai;->this$0:Llyiahf/vczjk/gi;

    invoke-interface {p1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
