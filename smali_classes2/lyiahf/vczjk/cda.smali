.class public final enum Llyiahf/vczjk/cda;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/cda;

.field public static final enum OooOOO0:Llyiahf/vczjk/cda;

.field public static final enum OooOOOO:Llyiahf/vczjk/cda;

.field public static final synthetic OooOOOo:[Llyiahf/vczjk/cda;


# instance fields
.field private final allowsInPosition:Z

.field private final allowsOutPosition:Z

.field private final label:Ljava/lang/String;

.field private final superpositionFactor:I


# direct methods
.method static constructor <clinit>()V
    .locals 9

    new-instance v0, Llyiahf/vczjk/cda;

    const-string v4, ""

    const/4 v5, 0x1

    const-string v3, "INVARIANT"

    const/4 v1, 0x0

    const/4 v6, 0x1

    const/4 v2, 0x0

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/cda;-><init>(IILjava/lang/String;Ljava/lang/String;ZZ)V

    sput-object v0, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    new-instance v1, Llyiahf/vczjk/cda;

    const-string v5, "in"

    const-string v4, "IN_VARIANCE"

    const/4 v2, 0x1

    const/4 v7, 0x0

    const/4 v3, -0x1

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/cda;-><init>(IILjava/lang/String;Ljava/lang/String;ZZ)V

    sput-object v1, Llyiahf/vczjk/cda;->OooOOO:Llyiahf/vczjk/cda;

    new-instance v2, Llyiahf/vczjk/cda;

    const-string v6, "out"

    const-string v5, "OUT_VARIANCE"

    const/4 v3, 0x2

    const/4 v8, 0x1

    const/4 v4, 0x1

    invoke-direct/range {v2 .. v8}, Llyiahf/vczjk/cda;-><init>(IILjava/lang/String;Ljava/lang/String;ZZ)V

    sput-object v2, Llyiahf/vczjk/cda;->OooOOOO:Llyiahf/vczjk/cda;

    filled-new-array {v0, v1, v2}, [Llyiahf/vczjk/cda;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/cda;->OooOOOo:[Llyiahf/vczjk/cda;

    invoke-static {v0}, Llyiahf/vczjk/yi4;->OoooO0([Ljava/lang/Enum;)Llyiahf/vczjk/np2;

    return-void
.end method

.method public constructor <init>(IILjava/lang/String;Ljava/lang/String;ZZ)V
    .locals 0

    invoke-direct {p0, p3, p1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    iput-object p4, p0, Llyiahf/vczjk/cda;->label:Ljava/lang/String;

    iput-boolean p5, p0, Llyiahf/vczjk/cda;->allowsInPosition:Z

    iput-boolean p6, p0, Llyiahf/vczjk/cda;->allowsOutPosition:Z

    iput p2, p0, Llyiahf/vczjk/cda;->superpositionFactor:I

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/cda;
    .locals 1

    const-class v0, Llyiahf/vczjk/cda;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/cda;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/cda;
    .locals 1

    sget-object v0, Llyiahf/vczjk/cda;->OooOOOo:[Llyiahf/vczjk/cda;

    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/cda;

    return-object v0
.end method


# virtual methods
.method public final OooO00o()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/cda;->allowsOutPosition:Z

    return v0
.end method

.method public final OooO0O0()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/cda;->label:Ljava/lang/String;

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/cda;->label:Ljava/lang/String;

    return-object v0
.end method
