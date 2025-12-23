.class public final Llyiahf/vczjk/yj6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $flingBehavior:Llyiahf/vczjk/o23;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/o23;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/yj6;->$flingBehavior:Llyiahf/vczjk/o23;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/yj6;->$flingBehavior:Llyiahf/vczjk/o23;

    instance-of v1, v0, Llyiahf/vczjk/kv8;

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/kv8;

    goto :goto_0

    :cond_0
    move-object v0, v2

    :goto_0
    if-eqz v0, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/kv8;->OooO0o:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Integer;

    return-object v0

    :cond_1
    return-object v2
.end method
