.class public final enum Llyiahf/vczjk/bo;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/bo;

.field public static final enum OooOOO0:Llyiahf/vczjk/bo;

.field public static final enum OooOOOO:Llyiahf/vczjk/bo;

.field public static final enum OooOOOo:Llyiahf/vczjk/bo;

.field public static final synthetic OooOOo:[Llyiahf/vczjk/bo;

.field public static final enum OooOOo0:Llyiahf/vczjk/bo;


# instance fields
.field private final javaTarget:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    new-instance v0, Llyiahf/vczjk/bo;

    const-string v1, "METHOD"

    const-string v2, "METHOD_RETURN_TYPE"

    const/4 v3, 0x0

    invoke-direct {v0, v2, v3, v1}, Llyiahf/vczjk/bo;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/bo;->OooOOO0:Llyiahf/vczjk/bo;

    new-instance v1, Llyiahf/vczjk/bo;

    const-string v2, "PARAMETER"

    const-string v3, "VALUE_PARAMETER"

    const/4 v4, 0x1

    invoke-direct {v1, v3, v4, v2}, Llyiahf/vczjk/bo;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    sput-object v1, Llyiahf/vczjk/bo;->OooOOO:Llyiahf/vczjk/bo;

    new-instance v2, Llyiahf/vczjk/bo;

    const-string v3, "FIELD"

    const/4 v4, 0x2

    invoke-direct {v2, v3, v4, v3}, Llyiahf/vczjk/bo;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    sput-object v2, Llyiahf/vczjk/bo;->OooOOOO:Llyiahf/vczjk/bo;

    new-instance v3, Llyiahf/vczjk/bo;

    const-string v4, "TYPE_USE"

    const/4 v5, 0x3

    invoke-direct {v3, v4, v5, v4}, Llyiahf/vczjk/bo;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    sput-object v3, Llyiahf/vczjk/bo;->OooOOOo:Llyiahf/vczjk/bo;

    move-object v5, v4

    new-instance v4, Llyiahf/vczjk/bo;

    const-string v6, "TYPE_PARAMETER_BOUNDS"

    const/4 v7, 0x4

    invoke-direct {v4, v6, v7, v5}, Llyiahf/vczjk/bo;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    sput-object v4, Llyiahf/vczjk/bo;->OooOOo0:Llyiahf/vczjk/bo;

    new-instance v5, Llyiahf/vczjk/bo;

    const-string v6, "TYPE_PARAMETER"

    const/4 v7, 0x5

    invoke-direct {v5, v6, v7, v6}, Llyiahf/vczjk/bo;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    filled-new-array/range {v0 .. v5}, [Llyiahf/vczjk/bo;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/bo;->OooOOo:[Llyiahf/vczjk/bo;

    invoke-static {v0}, Llyiahf/vczjk/yi4;->OoooO0([Ljava/lang/Enum;)Llyiahf/vczjk/np2;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    iput-object p3, p0, Llyiahf/vczjk/bo;->javaTarget:Ljava/lang/String;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/bo;
    .locals 1

    const-class v0, Llyiahf/vczjk/bo;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/bo;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/bo;
    .locals 1

    sget-object v0, Llyiahf/vczjk/bo;->OooOOo:[Llyiahf/vczjk/bo;

    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/bo;

    return-object v0
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bo;->javaTarget:Ljava/lang/String;

    return-object v0
.end method
