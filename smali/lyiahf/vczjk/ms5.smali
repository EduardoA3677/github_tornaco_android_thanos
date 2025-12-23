.class public final Llyiahf/vczjk/ms5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/Iterator;
.implements Llyiahf/vczjk/cg4;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/xf8;

.field public OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/ns5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ns5;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ms5;->OooOOOO:Llyiahf/vczjk/ns5;

    const/4 v0, -0x1

    iput v0, p0, Llyiahf/vczjk/ms5;->OooOOO0:I

    new-instance v0, Llyiahf/vczjk/ls5;

    const/4 v1, 0x0

    invoke-direct {v0, p1, p0, v1}, Llyiahf/vczjk/ls5;-><init>(Llyiahf/vczjk/ns5;Llyiahf/vczjk/ms5;Llyiahf/vczjk/yo1;)V

    invoke-static {v0}, Llyiahf/vczjk/vl6;->OooOo0(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/xf8;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ms5;->OooOOO:Llyiahf/vczjk/xf8;

    return-void
.end method


# virtual methods
.method public final hasNext()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ms5;->OooOOO:Llyiahf/vczjk/xf8;

    invoke-virtual {v0}, Llyiahf/vczjk/xf8;->hasNext()Z

    move-result v0

    return v0
.end method

.method public final next()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ms5;->OooOOO:Llyiahf/vczjk/xf8;

    invoke-virtual {v0}, Llyiahf/vczjk/xf8;->next()Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final remove()V
    .locals 3

    iget v0, p0, Llyiahf/vczjk/ms5;->OooOOO0:I

    const/4 v1, -0x1

    if-eq v0, v1, :cond_0

    iget-object v2, p0, Llyiahf/vczjk/ms5;->OooOOOO:Llyiahf/vczjk/ns5;

    iget-object v2, v2, Llyiahf/vczjk/ns5;->OooOOO:Llyiahf/vczjk/ks5;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/ks5;->OooOOO0(I)V

    iput v1, p0, Llyiahf/vczjk/ms5;->OooOOO0:I

    :cond_0
    return-void
.end method
