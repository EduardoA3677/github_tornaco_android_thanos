.class public abstract enum Llyiahf/vczjk/j4a;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/f4a;

.field public static final enum OooOOO0:Llyiahf/vczjk/h4a;

.field public static final enum OooOOOO:Llyiahf/vczjk/i4a;

.field public static final enum OooOOOo:Llyiahf/vczjk/g4a;

.field public static final synthetic OooOOo0:[Llyiahf/vczjk/j4a;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/h4a;

    invoke-direct {v0}, Llyiahf/vczjk/h4a;-><init>()V

    sput-object v0, Llyiahf/vczjk/j4a;->OooOOO0:Llyiahf/vczjk/h4a;

    new-instance v1, Llyiahf/vczjk/f4a;

    invoke-direct {v1}, Llyiahf/vczjk/f4a;-><init>()V

    sput-object v1, Llyiahf/vczjk/j4a;->OooOOO:Llyiahf/vczjk/f4a;

    new-instance v2, Llyiahf/vczjk/i4a;

    invoke-direct {v2}, Llyiahf/vczjk/i4a;-><init>()V

    sput-object v2, Llyiahf/vczjk/j4a;->OooOOOO:Llyiahf/vczjk/i4a;

    new-instance v3, Llyiahf/vczjk/g4a;

    invoke-direct {v3}, Llyiahf/vczjk/g4a;-><init>()V

    sput-object v3, Llyiahf/vczjk/j4a;->OooOOOo:Llyiahf/vczjk/g4a;

    const/4 v4, 0x4

    new-array v4, v4, [Llyiahf/vczjk/j4a;

    const/4 v5, 0x0

    aput-object v0, v4, v5

    const/4 v0, 0x1

    aput-object v1, v4, v0

    const/4 v0, 0x2

    aput-object v2, v4, v0

    const/4 v0, 0x3

    aput-object v3, v4, v0

    sput-object v4, Llyiahf/vczjk/j4a;->OooOOo0:[Llyiahf/vczjk/j4a;

    invoke-static {v4}, Llyiahf/vczjk/yi4;->OoooO0([Ljava/lang/Enum;)Llyiahf/vczjk/np2;

    return-void
.end method

.method public static OooO0O0(Llyiahf/vczjk/iaa;)Llyiahf/vczjk/j4a;
    .locals 2

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000o()Z

    move-result v0

    if-eqz v0, :cond_0

    sget-object p0, Llyiahf/vczjk/j4a;->OooOOO:Llyiahf/vczjk/f4a;

    return-object p0

    :cond_0
    instance-of v0, p0, Llyiahf/vczjk/a52;

    if-eqz v0, :cond_1

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/a52;

    :cond_1
    sget-object v0, Llyiahf/vczjk/uk2;->OooOo0:Llyiahf/vczjk/uk2;

    invoke-virtual {v0}, Llyiahf/vczjk/uk2;->o0000OOO()Llyiahf/vczjk/l3a;

    move-result-object v0

    invoke-static {p0}, Llyiahf/vczjk/u34;->Oooo0oO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/dp8;

    move-result-object p0

    sget-object v1, Llyiahf/vczjk/k3a;->OooO0oo:Llyiahf/vczjk/k3a;

    invoke-static {v0, p0, v1}, Llyiahf/vczjk/ye5;->OooOo(Llyiahf/vczjk/l3a;Llyiahf/vczjk/pt7;Llyiahf/vczjk/wr6;)Z

    move-result p0

    if-eqz p0, :cond_2

    sget-object p0, Llyiahf/vczjk/j4a;->OooOOOo:Llyiahf/vczjk/g4a;

    return-object p0

    :cond_2
    sget-object p0, Llyiahf/vczjk/j4a;->OooOOOO:Llyiahf/vczjk/i4a;

    return-object p0
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/j4a;
    .locals 1

    const-class v0, Llyiahf/vczjk/j4a;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/j4a;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/j4a;
    .locals 1

    sget-object v0, Llyiahf/vczjk/j4a;->OooOOo0:[Llyiahf/vczjk/j4a;

    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/j4a;

    return-object v0
.end method


# virtual methods
.method public abstract OooO00o(Llyiahf/vczjk/iaa;)Llyiahf/vczjk/j4a;
.end method
