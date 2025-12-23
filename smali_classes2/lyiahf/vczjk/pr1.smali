.class public final Llyiahf/vczjk/pr1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/nr1;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/nr1;

.field public final OooOOO0:Llyiahf/vczjk/oe3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nr1;Llyiahf/vczjk/oe3;)V
    .locals 1

    const-string v0, "baseKey"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/pr1;->OooOOO0:Llyiahf/vczjk/oe3;

    instance-of p2, p1, Llyiahf/vczjk/pr1;

    if-eqz p2, :cond_0

    check-cast p1, Llyiahf/vczjk/pr1;

    iget-object p1, p1, Llyiahf/vczjk/pr1;->OooOOO:Llyiahf/vczjk/nr1;

    :cond_0
    iput-object p1, p0, Llyiahf/vczjk/pr1;->OooOOO:Llyiahf/vczjk/nr1;

    return-void
.end method
