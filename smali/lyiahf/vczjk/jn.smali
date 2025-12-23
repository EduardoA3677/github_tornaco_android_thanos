.class public final Llyiahf/vczjk/jn;
.super Llyiahf/vczjk/yi4;
.source "SourceFile"


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/jn;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/jn;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/jn;->OooOOOO:Llyiahf/vczjk/jn;

    return-void
.end method


# virtual methods
.method public final OooOoO0(Ljava/lang/annotation/Annotation;)Llyiahf/vczjk/yi4;
    .locals 2

    new-instance v0, Llyiahf/vczjk/nn;

    invoke-interface {p1}, Ljava/lang/annotation/Annotation;->annotationType()Ljava/lang/Class;

    move-result-object v1

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v1, v0, Llyiahf/vczjk/nn;->OooOOOO:Ljava/lang/Class;

    iput-object p1, v0, Llyiahf/vczjk/nn;->OooOOOo:Ljava/lang/annotation/Annotation;

    return-object v0
.end method

.method public final OooOoOO()Llyiahf/vczjk/ao;
    .locals 1

    new-instance v0, Llyiahf/vczjk/ao;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    return-object v0
.end method

.method public final OooOoo0()Llyiahf/vczjk/lo;
    .locals 1

    sget-object v0, Llyiahf/vczjk/yi4;->OooO00o:Llyiahf/vczjk/ln;

    return-object v0
.end method

.method public final OooooO0(Ljava/lang/annotation/Annotation;)Z
    .locals 0

    const/4 p1, 0x0

    return p1
.end method
