.class public final Llyiahf/vczjk/v48;
.super Llyiahf/vczjk/w48;
.source "SourceFile"

# interfaces
.implements Ljava/util/Iterator;


# instance fields
.field public OooOOO:Z

.field public OooOOO0:Llyiahf/vczjk/u48;

.field public final synthetic OooOOOO:Llyiahf/vczjk/x48;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/x48;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/v48;->OooOOOO:Llyiahf/vczjk/x48;

    const/4 p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/v48;->OooOOO:Z

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/u48;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v48;->OooOOO0:Llyiahf/vczjk/u48;

    if-ne p1, v0, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/u48;->OooOOOo:Llyiahf/vczjk/u48;

    iput-object p1, p0, Llyiahf/vczjk/v48;->OooOOO0:Llyiahf/vczjk/u48;

    if-nez p1, :cond_0

    const/4 p1, 0x1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    iput-boolean p1, p0, Llyiahf/vczjk/v48;->OooOOO:Z

    :cond_1
    return-void
.end method

.method public final hasNext()Z
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/v48;->OooOOO:Z

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/v48;->OooOOOO:Llyiahf/vczjk/x48;

    iget-object v0, v0, Llyiahf/vczjk/x48;->OooOOO0:Llyiahf/vczjk/u48;

    if-eqz v0, :cond_0

    return v2

    :cond_0
    return v1

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/v48;->OooOOO0:Llyiahf/vczjk/u48;

    if-eqz v0, :cond_2

    iget-object v0, v0, Llyiahf/vczjk/u48;->OooOOOO:Llyiahf/vczjk/u48;

    if-eqz v0, :cond_2

    return v2

    :cond_2
    return v1
.end method

.method public final next()Ljava/lang/Object;
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/v48;->OooOOO:Z

    if-eqz v0, :cond_0

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/v48;->OooOOO:Z

    iget-object v0, p0, Llyiahf/vczjk/v48;->OooOOOO:Llyiahf/vczjk/x48;

    iget-object v0, v0, Llyiahf/vczjk/x48;->OooOOO0:Llyiahf/vczjk/u48;

    iput-object v0, p0, Llyiahf/vczjk/v48;->OooOOO0:Llyiahf/vczjk/u48;

    goto :goto_1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/v48;->OooOOO0:Llyiahf/vczjk/u48;

    if-eqz v0, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/u48;->OooOOOO:Llyiahf/vczjk/u48;

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_0
    iput-object v0, p0, Llyiahf/vczjk/v48;->OooOOO0:Llyiahf/vczjk/u48;

    :goto_1
    iget-object v0, p0, Llyiahf/vczjk/v48;->OooOOO0:Llyiahf/vczjk/u48;

    return-object v0
.end method
