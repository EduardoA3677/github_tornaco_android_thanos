.class public final Llyiahf/vczjk/e9;
.super Llyiahf/vczjk/fu6;
.source "SourceFile"


# instance fields
.field public final OooO0Oo:I


# direct methods
.method public constructor <init>(I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/e9;->OooO0Oo:I

    return-void
.end method


# virtual methods
.method public final OooOOO0(Llyiahf/vczjk/js8;)Ljava/lang/Object;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/e9;->OooO0Oo:I

    iget-boolean v1, p1, Llyiahf/vczjk/js8;->OooOOoo:Z

    if-eqz v1, :cond_0

    const-string v1, "use active SlotWriter to create an anchor location instead"

    invoke-static {v1}, Llyiahf/vczjk/ag1;->OooO0OO(Ljava/lang/String;)V

    :cond_0
    if-ltz v0, :cond_1

    iget v1, p1, Llyiahf/vczjk/js8;->OooOOO:I

    if-ge v0, v1, :cond_1

    goto :goto_0

    :cond_1
    const-string v1, "Parameter index is out of range"

    invoke-static {v1}, Llyiahf/vczjk/v07;->OooO00o(Ljava/lang/String;)V

    :goto_0
    iget-object v1, p1, Llyiahf/vczjk/js8;->OooOo0:Ljava/util/ArrayList;

    iget p1, p1, Llyiahf/vczjk/js8;->OooOOO:I

    invoke-static {v1, v0, p1}, Llyiahf/vczjk/ls8;->OooO0o(Ljava/util/ArrayList;II)I

    move-result p1

    if-gez p1, :cond_2

    new-instance v2, Llyiahf/vczjk/d7;

    invoke-direct {v2, v0}, Llyiahf/vczjk/d7;-><init>(I)V

    add-int/lit8 p1, p1, 0x1

    neg-int p1, p1

    invoke-virtual {v1, p1, v2}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    goto :goto_1

    :cond_2
    invoke-virtual {v1, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object p1

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/d7;

    :goto_1
    return-object v2
.end method
