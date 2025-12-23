.class public final Llyiahf/vczjk/gj8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/hj8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hj8;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/gj8;->this$0:Llyiahf/vczjk/hj8;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/gj8;->this$0:Llyiahf/vczjk/hj8;

    iget-object v0, v0, Llyiahf/vczjk/hj8;->OooOOOO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/tq8;

    iget-wide v0, v0, Llyiahf/vczjk/tq8;->OooO00o:J

    const-wide v2, 0x7fc000007fc00000L    # 2.247117487993712E307

    cmp-long v0, v0, v2

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/gj8;->this$0:Llyiahf/vczjk/hj8;

    iget-object v0, v0, Llyiahf/vczjk/hj8;->OooOOOO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/tq8;

    iget-wide v0, v0, Llyiahf/vczjk/tq8;->OooO00o:J

    invoke-static {v0, v1}, Llyiahf/vczjk/tq8;->OooO0o0(J)Z

    move-result v0

    if-eqz v0, :cond_1

    :goto_0
    const/4 v0, 0x0

    return-object v0

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/gj8;->this$0:Llyiahf/vczjk/hj8;

    iget-object v1, v0, Llyiahf/vczjk/hj8;->OooOOO0:Llyiahf/vczjk/fj8;

    iget-object v0, v0, Llyiahf/vczjk/hj8;->OooOOOO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/tq8;

    iget-wide v2, v0, Llyiahf/vczjk/tq8;->OooO00o:J

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/fj8;->OooO0O0(J)Landroid/graphics/Shader;

    move-result-object v0

    return-object v0
.end method
