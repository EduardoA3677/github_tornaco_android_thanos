.class public final Llyiahf/vczjk/xr5;
.super Llyiahf/vczjk/mb5;
.source "SourceFile"


# instance fields
.field public final OooOOOo:Llyiahf/vczjk/us6;

.field public OooOOo0:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/us6;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    const/4 v0, 0x0

    invoke-direct {p0, v0, p2, p3}, Llyiahf/vczjk/mb5;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/xr5;->OooOOOo:Llyiahf/vczjk/us6;

    iput-object p3, p0, Llyiahf/vczjk/xr5;->OooOOo0:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final getValue()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/xr5;->OooOOo0:Ljava/lang/Object;

    return-object v0
.end method

.method public final setValue(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/xr5;->OooOOo0:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/xr5;->OooOOo0:Ljava/lang/Object;

    iget-object v1, p0, Llyiahf/vczjk/xr5;->OooOOOo:Llyiahf/vczjk/us6;

    iget-object v1, v1, Llyiahf/vczjk/us6;->OooOOO:Ljava/util/Iterator;

    check-cast v1, Llyiahf/vczjk/ss6;

    iget-object v2, v1, Llyiahf/vczjk/ss6;->OooOOOo:Llyiahf/vczjk/ns6;

    iget-object v3, p0, Llyiahf/vczjk/mb5;->OooOOO:Ljava/lang/Object;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/ns6;->containsKey(Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_0

    return-object v0

    :cond_0
    iget-boolean v4, v1, Llyiahf/vczjk/rs6;->OooOOOO:Z

    if-eqz v4, :cond_3

    if-eqz v4, :cond_2

    iget-object v4, v1, Llyiahf/vczjk/rs6;->OooOOO0:[Llyiahf/vczjk/k0a;

    iget v5, v1, Llyiahf/vczjk/rs6;->OooOOO:I

    aget-object v4, v4, v5

    iget-object v5, v4, Llyiahf/vczjk/k0a;->OooOOO0:[Ljava/lang/Object;

    iget v4, v4, Llyiahf/vczjk/k0a;->OooOOOO:I

    aget-object v4, v5, v4

    invoke-virtual {v2, v3, p1}, Llyiahf/vczjk/ns6;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 p1, 0x0

    if-eqz v4, :cond_1

    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    move-result v3

    goto :goto_0

    :cond_1
    move v3, p1

    :goto_0
    iget-object v5, v2, Llyiahf/vczjk/ns6;->OooOOO:Llyiahf/vczjk/j0a;

    invoke-virtual {v1, v3, v5, v4, p1}, Llyiahf/vczjk/ss6;->OooO0Oo(ILlyiahf/vczjk/j0a;Ljava/lang/Object;I)V

    goto :goto_1

    :cond_2
    new-instance p1, Ljava/util/NoSuchElementException;

    invoke-direct {p1}, Ljava/util/NoSuchElementException;-><init>()V

    throw p1

    :cond_3
    invoke-virtual {v2, v3, p1}, Llyiahf/vczjk/ns6;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :goto_1
    iget p1, v2, Llyiahf/vczjk/ns6;->OooOOOo:I

    iput p1, v1, Llyiahf/vczjk/ss6;->OooOOoo:I

    return-object v0
.end method
