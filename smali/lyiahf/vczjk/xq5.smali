.class public final Llyiahf/vczjk/xq5;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/yq5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/yq5;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yq5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/xq5;->this$0:Llyiahf/vczjk/yq5;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/xq5;->this$0:Llyiahf/vczjk/yq5;

    iget-object v0, v0, Llyiahf/vczjk/yq5;->OooO0O0:Llyiahf/vczjk/jn0;

    iget-object v0, v0, Llyiahf/vczjk/jn0;->OooO00o:Llyiahf/vczjk/h23;

    iget-object v0, v0, Llyiahf/vczjk/h23;->OooO00o:Llyiahf/vczjk/i23;

    invoke-virtual {v0}, Llyiahf/vczjk/i23;->OooO0O0()Ljava/util/List;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/d21;->oo000o(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/li6;

    if-eqz v0, :cond_0

    instance-of v1, v0, Llyiahf/vczjk/ii6;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/ii6;

    sget-object v1, Llyiahf/vczjk/s25;->OooOOO0:Llyiahf/vczjk/s25;

    iget-object v2, v0, Llyiahf/vczjk/ii6;->OooO00o:Llyiahf/vczjk/s25;

    if-ne v2, v1, :cond_0

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method
