.class public final Llyiahf/vczjk/en9;
.super Llyiahf/vczjk/pca;
.source "SourceFile"


# static fields
.field public static final OooOOO0:Llyiahf/vczjk/en9;

.field private static final serialVersionUID:J = 0x2L


# instance fields
.field protected final _value:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/en9;

    const-string v1, ""

    invoke-direct {v0, v1}, Llyiahf/vczjk/en9;-><init>(Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/en9;->OooOOO0:Llyiahf/vczjk/en9;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/en9;->_value:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 0

    iget-object p2, p0, Llyiahf/vczjk/en9;->_value:Ljava/lang/String;

    if-nez p2, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/u94;->o00000oo()V

    return-void

    :cond_0
    invoke-virtual {p1, p2}, Llyiahf/vczjk/u94;->o0000ooO(Ljava/lang/String;)V

    return-void
.end method

.method public final OooO0o()Llyiahf/vczjk/gc4;
    .locals 1

    sget-object v0, Llyiahf/vczjk/gc4;->OooOo00:Llyiahf/vczjk/gc4;

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    if-ne p1, p0, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 v0, 0x0

    if-nez p1, :cond_1

    return v0

    :cond_1
    instance-of v1, p1, Llyiahf/vczjk/en9;

    if-eqz v1, :cond_2

    check-cast p1, Llyiahf/vczjk/en9;

    iget-object p1, p1, Llyiahf/vczjk/en9;->_value:Ljava/lang/String;

    iget-object v0, p0, Llyiahf/vczjk/en9;->_value:Ljava/lang/String;

    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    return p1

    :cond_2
    return v0
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/en9;->_value:Ljava/lang/String;

    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    move-result v0

    return v0
.end method
