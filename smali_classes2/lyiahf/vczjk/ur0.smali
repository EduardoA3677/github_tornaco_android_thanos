.class public final enum Llyiahf/vczjk/ur0;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/ur0;

.field public static final enum OooOOO0:Llyiahf/vczjk/ur0;

.field public static final enum OooOOOO:Llyiahf/vczjk/ur0;

.field public static final synthetic OooOOOo:[Llyiahf/vczjk/ur0;

.field public static final synthetic OooOOo0:Llyiahf/vczjk/np2;


# instance fields
.field private final labelRes:I

.field private final withAllowed:Z

.field private final withBlocked:Z


# direct methods
.method static constructor <clinit>()V
    .locals 8

    new-instance v0, Llyiahf/vczjk/ur0;

    sget v3, Lgithub/tornaco/android/thanos/res/R$string;->start_record_allowed:I

    const-string v1, "Allowed"

    const/4 v2, 0x0

    const/4 v4, 0x1

    const/4 v5, 0x0

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/ur0;-><init>(Ljava/lang/String;IIZZ)V

    sput-object v0, Llyiahf/vczjk/ur0;->OooOOO0:Llyiahf/vczjk/ur0;

    new-instance v1, Llyiahf/vczjk/ur0;

    sget v4, Lgithub/tornaco/android/thanos/res/R$string;->start_record_blocked:I

    const-string v2, "Blocked"

    const/4 v3, 0x1

    const/4 v6, 0x1

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/ur0;-><init>(Ljava/lang/String;IIZZ)V

    sput-object v1, Llyiahf/vczjk/ur0;->OooOOO:Llyiahf/vczjk/ur0;

    new-instance v2, Llyiahf/vczjk/ur0;

    sget v5, Lgithub/tornaco/android/thanos/res/R$string;->start_record_merged:I

    const-string v3, "Merged"

    const/4 v4, 0x2

    const/4 v7, 0x1

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/ur0;-><init>(Ljava/lang/String;IIZZ)V

    sput-object v2, Llyiahf/vczjk/ur0;->OooOOOO:Llyiahf/vczjk/ur0;

    filled-new-array {v0, v1, v2}, [Llyiahf/vczjk/ur0;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/ur0;->OooOOOo:[Llyiahf/vczjk/ur0;

    invoke-static {v0}, Llyiahf/vczjk/yi4;->OoooO0([Ljava/lang/Enum;)Llyiahf/vczjk/np2;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/ur0;->OooOOo0:Llyiahf/vczjk/np2;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;IIZZ)V
    .locals 0

    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    iput p3, p0, Llyiahf/vczjk/ur0;->labelRes:I

    iput-boolean p4, p0, Llyiahf/vczjk/ur0;->withAllowed:Z

    iput-boolean p5, p0, Llyiahf/vczjk/ur0;->withBlocked:Z

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/ur0;
    .locals 1

    const-class v0, Llyiahf/vczjk/ur0;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/ur0;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/ur0;
    .locals 1

    sget-object v0, Llyiahf/vczjk/ur0;->OooOOOo:[Llyiahf/vczjk/ur0;

    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/ur0;

    return-object v0
.end method


# virtual methods
.method public final OooO00o()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/ur0;->labelRes:I

    return v0
.end method

.method public final OooO0O0()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/ur0;->withAllowed:Z

    return v0
.end method

.method public final OooO0OO()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/ur0;->withBlocked:Z

    return v0
.end method
