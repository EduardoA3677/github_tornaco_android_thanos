.class public Llyiahf/vczjk/x25;
.super Llyiahf/vczjk/dha;
.source "SourceFile"


# static fields
.field public static final OooO0Oo:Llyiahf/vczjk/ad3;


# instance fields
.field public final OooO0O0:Llyiahf/vczjk/ly8;

.field public OooO0OO:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/ad3;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/ad3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/x25;->OooO0Oo:Llyiahf/vczjk/ad3;

    return-void
.end method

.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Llyiahf/vczjk/dha;-><init>()V

    new-instance v0, Llyiahf/vczjk/ly8;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/ly8;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/x25;->OooO0O0:Llyiahf/vczjk/ly8;

    iput-boolean v1, p0, Llyiahf/vczjk/x25;->OooO0OO:Z

    return-void
.end method


# virtual methods
.method public final OooO0Oo()V
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/x25;->OooO0O0:Llyiahf/vczjk/ly8;

    invoke-virtual {v0}, Llyiahf/vczjk/ly8;->OooO0oO()I

    move-result v1

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    if-ge v3, v1, :cond_0

    invoke-virtual {v0, v3}, Llyiahf/vczjk/ly8;->OooO0oo(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/v25;

    const/4 v5, 0x1

    invoke-virtual {v4, v5}, Llyiahf/vczjk/v25;->OooOO0O(Z)Llyiahf/vczjk/vy2;

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    iget v1, v0, Llyiahf/vczjk/ly8;->OooOOOo:I

    iget-object v3, v0, Llyiahf/vczjk/ly8;->OooOOOO:[Ljava/lang/Object;

    move v4, v2

    :goto_1
    if-ge v4, v1, :cond_1

    const/4 v5, 0x0

    aput-object v5, v3, v4

    add-int/lit8 v4, v4, 0x1

    goto :goto_1

    :cond_1
    iput v2, v0, Llyiahf/vczjk/ly8;->OooOOOo:I

    iput-boolean v2, v0, Llyiahf/vczjk/ly8;->OooOOO0:Z

    return-void
.end method
