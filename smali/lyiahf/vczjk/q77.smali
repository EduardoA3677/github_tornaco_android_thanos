.class public final Llyiahf/vczjk/q77;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/p77;
.implements Llyiahf/vczjk/qs5;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/qs5;

.field public final OooOOO0:Llyiahf/vczjk/or1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/or1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/q77;->OooOOO0:Llyiahf/vczjk/or1;

    iput-object p1, p0, Llyiahf/vczjk/q77;->OooOOO:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final OoooOO0()Llyiahf/vczjk/or1;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q77;->OooOOO0:Llyiahf/vczjk/or1;

    return-object v0
.end method

.method public final getValue()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q77;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final setValue(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q77;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v0, p1}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    return-void
.end method
