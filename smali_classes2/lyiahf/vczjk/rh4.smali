.class public final Llyiahf/vczjk/rh4;
.super Llyiahf/vczjk/xh4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final OooOOo:Llyiahf/vczjk/sh4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/sh4;)V
    .locals 1

    const-string v0, "property"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Llyiahf/vczjk/xh4;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/rh4;->OooOOo:Llyiahf/vczjk/sh4;

    return-void
.end method


# virtual methods
.method public final OooO0oO()Llyiahf/vczjk/th4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rh4;->OooOOo:Llyiahf/vczjk/sh4;

    return-object v0
.end method

.method public final OooOo00()Llyiahf/vczjk/ai4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rh4;->OooOOo:Llyiahf/vczjk/sh4;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rh4;->OooOOo:Llyiahf/vczjk/sh4;

    iget-object v0, v0, Llyiahf/vczjk/sh4;->OooOo0O:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/rh4;

    filled-new-array {p1, p2}, [Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ff4;->OooO0oo([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
