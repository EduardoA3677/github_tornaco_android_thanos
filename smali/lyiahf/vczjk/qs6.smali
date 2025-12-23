.class public Llyiahf/vczjk/qs6;
.super Llyiahf/vczjk/o00O00OO;
.source "SourceFile"


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/qs6;


# instance fields
.field public final OooOOO:I

.field public final OooOOO0:Llyiahf/vczjk/j0a;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/qs6;

    sget-object v1, Llyiahf/vczjk/j0a;->OooO0o0:Llyiahf/vczjk/j0a;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/qs6;-><init>(Llyiahf/vczjk/j0a;I)V

    sput-object v0, Llyiahf/vczjk/qs6;->OooOOOO:Llyiahf/vczjk/qs6;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/j0a;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/qs6;->OooOOO0:Llyiahf/vczjk/j0a;

    iput p2, p0, Llyiahf/vczjk/qs6;->OooOOO:I

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/Object;Llyiahf/vczjk/r05;)Llyiahf/vczjk/qs6;
    .locals 3

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    move-result v1

    goto :goto_0

    :cond_0
    move v1, v0

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/qs6;->OooOOO0:Llyiahf/vczjk/j0a;

    invoke-virtual {v2, v1, p1, v0, p2}, Llyiahf/vczjk/j0a;->OooOo0(ILjava/lang/Object;ILjava/lang/Object;)Llyiahf/vczjk/w3;

    move-result-object p1

    if-nez p1, :cond_1

    return-object p0

    :cond_1
    new-instance p2, Llyiahf/vczjk/qs6;

    iget-object v0, p1, Llyiahf/vczjk/w3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/j0a;

    iget v1, p0, Llyiahf/vczjk/qs6;->OooOOO:I

    iget p1, p1, Llyiahf/vczjk/w3;->OooOOO0:I

    add-int/2addr v1, p1

    invoke-direct {p2, v0, v1}, Llyiahf/vczjk/qs6;-><init>(Llyiahf/vczjk/j0a;I)V

    return-object p2
.end method

.method public containsKey(Ljava/lang/Object;)Z
    .locals 3

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    move-result v1

    goto :goto_0

    :cond_0
    move v1, v0

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/qs6;->OooOOO0:Llyiahf/vczjk/j0a;

    invoke-virtual {v2, v1, v0, p1}, Llyiahf/vczjk/j0a;->OooO0Oo(IILjava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    move-result v1

    goto :goto_0

    :cond_0
    move v1, v0

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/qs6;->OooOOO0:Llyiahf/vczjk/j0a;

    invoke-virtual {v2, v1, v0, p1}, Llyiahf/vczjk/j0a;->OooO0oO(IILjava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
