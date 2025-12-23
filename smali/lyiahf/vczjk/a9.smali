.class public final Llyiahf/vczjk/a9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/d9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/d9;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/d9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/a9;->this$0:Llyiahf/vczjk/d9;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/a9;->this$0:Llyiahf/vczjk/d9;

    iget-object v0, v0, Llyiahf/vczjk/d9;->OooOO0o:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/a9;->this$0:Llyiahf/vczjk/d9;

    invoke-virtual {v0}, Llyiahf/vczjk/d9;->OooO0o0()F

    move-result v1

    invoke-static {v1}, Ljava/lang/Float;->isNaN(F)Z

    move-result v2

    iget-object v3, v0, Llyiahf/vczjk/d9;->OooO0oO:Llyiahf/vczjk/qs5;

    if-nez v2, :cond_0

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v2

    const/4 v3, 0x0

    invoke-virtual {v0, v1, v3, v2}, Llyiahf/vczjk/d9;->OooO0OO(FFLjava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0

    :cond_0
    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    :cond_1
    return-object v0
.end method
