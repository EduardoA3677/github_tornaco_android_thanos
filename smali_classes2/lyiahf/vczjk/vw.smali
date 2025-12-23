.class public final enum Llyiahf/vczjk/vw;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/vw;

.field public static final enum OooOOO0:Llyiahf/vczjk/vw;

.field public static final enum OooOOOO:Llyiahf/vczjk/vw;

.field public static final enum OooOOOo:Llyiahf/vczjk/vw;

.field public static final synthetic OooOOo:[Llyiahf/vczjk/vw;

.field public static final enum OooOOo0:Llyiahf/vczjk/vw;

.field public static final synthetic OooOOoo:Llyiahf/vczjk/np2;


# instance fields
.field private final labelRes:I

.field private final provider:Llyiahf/vczjk/uw;


# direct methods
.method static constructor <clinit>()V
    .locals 16

    new-instance v0, Llyiahf/vczjk/vw;

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->common_sort_by_default:I

    new-instance v2, Llyiahf/vczjk/sw7;

    const/4 v3, 0x5

    invoke-direct {v2, v3}, Llyiahf/vczjk/sw7;-><init>(I)V

    const-string v3, "Default"

    const/4 v4, 0x0

    invoke-direct {v0, v3, v4, v1, v2}, Llyiahf/vczjk/vw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/uw;)V

    sput-object v0, Llyiahf/vczjk/vw;->OooOOO0:Llyiahf/vczjk/vw;

    new-instance v1, Llyiahf/vczjk/vw;

    sget v2, Lgithub/tornaco/android/thanos/res/R$string;->enabled:I

    new-instance v3, Llyiahf/vczjk/xj0;

    const/16 v4, 0xb

    invoke-direct {v3, v4}, Llyiahf/vczjk/xj0;-><init>(I)V

    const-string v4, "CheckState"

    const/4 v5, 0x1

    invoke-direct {v1, v4, v5, v2, v3}, Llyiahf/vczjk/vw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/uw;)V

    sput-object v1, Llyiahf/vczjk/vw;->OooOOO:Llyiahf/vczjk/vw;

    new-instance v2, Llyiahf/vczjk/vw;

    sget v3, Lgithub/tornaco/android/thanos/res/R$string;->nav_title_settings:I

    new-instance v4, Llyiahf/vczjk/uk2;

    const/16 v5, 0xb

    invoke-direct {v4, v5}, Llyiahf/vczjk/uk2;-><init>(I)V

    const-string v5, "OptionState"

    const/4 v6, 0x2

    invoke-direct {v2, v5, v6, v3, v4}, Llyiahf/vczjk/vw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/uw;)V

    sput-object v2, Llyiahf/vczjk/vw;->OooOOOO:Llyiahf/vczjk/vw;

    new-instance v3, Llyiahf/vczjk/vw;

    sget v4, Lgithub/tornaco/android/thanos/res/R$string;->chip_title_app_only_running:I

    new-instance v5, Llyiahf/vczjk/op3;

    const/16 v6, 0xb

    invoke-direct {v5, v6}, Llyiahf/vczjk/op3;-><init>(I)V

    const-string v6, "Running"

    const/4 v7, 0x3

    invoke-direct {v3, v6, v7, v4, v5}, Llyiahf/vczjk/vw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/uw;)V

    new-instance v4, Llyiahf/vczjk/vw;

    sget v5, Lgithub/tornaco/android/thanos/res/R$string;->common_sort_by_install_app_label:I

    new-instance v6, Llyiahf/vczjk/pp3;

    const/16 v7, 0xb

    invoke-direct {v6, v7}, Llyiahf/vczjk/pp3;-><init>(I)V

    const-string v7, "AppLabel"

    const/4 v8, 0x4

    invoke-direct {v4, v7, v8, v5, v6}, Llyiahf/vczjk/vw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/uw;)V

    new-instance v5, Llyiahf/vczjk/vw;

    sget v6, Lgithub/tornaco/android/thanos/res/R$string;->common_sort_by_install_time:I

    new-instance v7, Llyiahf/vczjk/qp3;

    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    const-string v8, "InstallTime"

    const/4 v9, 0x5

    invoke-direct {v5, v8, v9, v6, v7}, Llyiahf/vczjk/vw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/uw;)V

    new-instance v6, Llyiahf/vczjk/vw;

    sget v7, Lgithub/tornaco/android/thanos/res/R$string;->common_sort_by_update_time:I

    new-instance v8, Llyiahf/vczjk/rp3;

    const/16 v9, 0xb

    invoke-direct {v8, v9}, Llyiahf/vczjk/rp3;-><init>(I)V

    const-string v9, "UpdateTime"

    const/4 v10, 0x6

    invoke-direct {v6, v9, v10, v7, v8}, Llyiahf/vczjk/vw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/uw;)V

    new-instance v7, Llyiahf/vczjk/vw;

    sget v8, Lgithub/tornaco/android/thanos/res/R$string;->common_sort_by_last_used_time:I

    new-instance v9, Llyiahf/vczjk/sp3;

    invoke-direct {v9}, Ljava/lang/Object;-><init>()V

    const-string v10, "LastUsedTime"

    const/4 v11, 0x7

    invoke-direct {v7, v10, v11, v8, v9}, Llyiahf/vczjk/vw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/uw;)V

    sput-object v7, Llyiahf/vczjk/vw;->OooOOOo:Llyiahf/vczjk/vw;

    new-instance v8, Llyiahf/vczjk/vw;

    sget v9, Lgithub/tornaco/android/thanos/res/R$string;->common_sort_by_total_used_time:I

    new-instance v10, Llyiahf/vczjk/tp3;

    const/16 v11, 0xb

    invoke-direct {v10, v11}, Llyiahf/vczjk/tp3;-><init>(I)V

    const-string v11, "TotalUsedTime"

    const/16 v12, 0x8

    invoke-direct {v8, v11, v12, v9, v10}, Llyiahf/vczjk/vw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/uw;)V

    sput-object v8, Llyiahf/vczjk/vw;->OooOOo0:Llyiahf/vczjk/vw;

    new-instance v9, Llyiahf/vczjk/vw;

    sget v10, Lgithub/tornaco/android/thanos/res/R$string;->common_sort_by_install_sdk_version:I

    new-instance v11, Llyiahf/vczjk/wp3;

    const/16 v12, 0xa

    invoke-direct {v11, v12}, Llyiahf/vczjk/wp3;-><init>(I)V

    const-string v12, "SdkVersion"

    const/16 v13, 0x9

    invoke-direct {v9, v12, v13, v10, v11}, Llyiahf/vczjk/vw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/uw;)V

    new-instance v10, Llyiahf/vczjk/vw;

    sget v11, Lgithub/tornaco/android/thanos/res/R$string;->common_sort_by_install_apk_size:I

    new-instance v12, Llyiahf/vczjk/e86;

    const/16 v13, 0xa

    invoke-direct {v12, v13}, Llyiahf/vczjk/e86;-><init>(I)V

    const-string v13, "ApkSize"

    const/16 v14, 0xa

    invoke-direct {v10, v13, v14, v11, v12}, Llyiahf/vczjk/vw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/uw;)V

    new-instance v11, Llyiahf/vczjk/vw;

    sget v12, Lgithub/tornaco/android/thanos/res/R$string;->common_sort_by_install_app_uid:I

    new-instance v13, Llyiahf/vczjk/ws7;

    const/16 v14, 0xa

    invoke-direct {v13, v14}, Llyiahf/vczjk/ws7;-><init>(I)V

    const-string v14, "AppUid"

    const/16 v15, 0xb

    invoke-direct {v11, v14, v15, v12, v13}, Llyiahf/vczjk/vw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/uw;)V

    filled-new-array/range {v0 .. v11}, [Llyiahf/vczjk/vw;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/vw;->OooOOo:[Llyiahf/vczjk/vw;

    invoke-static {v0}, Llyiahf/vczjk/yi4;->OoooO0([Ljava/lang/Enum;)Llyiahf/vczjk/np2;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/vw;->OooOOoo:Llyiahf/vczjk/np2;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;IILlyiahf/vczjk/uw;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    iput p3, p0, Llyiahf/vczjk/vw;->labelRes:I

    iput-object p4, p0, Llyiahf/vczjk/vw;->provider:Llyiahf/vczjk/uw;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/vw;
    .locals 1

    const-class v0, Llyiahf/vczjk/vw;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/vw;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/vw;
    .locals 1

    sget-object v0, Llyiahf/vczjk/vw;->OooOOo:[Llyiahf/vczjk/vw;

    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/vw;

    return-object v0
.end method


# virtual methods
.method public final OooO00o()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/vw;->labelRes:I

    return v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/uw;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vw;->provider:Llyiahf/vczjk/uw;

    return-object v0
.end method
