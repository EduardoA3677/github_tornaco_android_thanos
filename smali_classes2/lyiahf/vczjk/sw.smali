.class public final enum Llyiahf/vczjk/sw;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/sw;

.field public static final enum OooOOO0:Llyiahf/vczjk/sw;

.field public static final enum OooOOOO:Llyiahf/vczjk/sw;

.field public static final synthetic OooOOOo:[Llyiahf/vczjk/sw;


# instance fields
.field public final labelRes:I

.field public final provider:Llyiahf/vczjk/rw;


# direct methods
.method static constructor <clinit>()V
    .locals 14

    new-instance v0, Llyiahf/vczjk/sw;

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->common_sort_by_default:I

    new-instance v2, Llyiahf/vczjk/uk2;

    const/16 v3, 0xa

    invoke-direct {v2, v3}, Llyiahf/vczjk/uk2;-><init>(I)V

    const-string v3, "Default"

    const/4 v4, 0x0

    invoke-direct {v0, v3, v4, v1, v2}, Llyiahf/vczjk/sw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/rw;)V

    sput-object v0, Llyiahf/vczjk/sw;->OooOOO0:Llyiahf/vczjk/sw;

    new-instance v1, Llyiahf/vczjk/sw;

    sget v2, Lgithub/tornaco/android/thanos/res/R$string;->chip_title_app_only_running:I

    new-instance v3, Llyiahf/vczjk/op3;

    const/16 v4, 0xa

    invoke-direct {v3, v4}, Llyiahf/vczjk/op3;-><init>(I)V

    const-string v4, "Running"

    const/4 v5, 0x1

    invoke-direct {v1, v4, v5, v2, v3}, Llyiahf/vczjk/sw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/rw;)V

    new-instance v2, Llyiahf/vczjk/sw;

    sget v3, Lgithub/tornaco/android/thanos/res/R$string;->common_sort_by_install_app_label:I

    new-instance v4, Llyiahf/vczjk/pp3;

    const/16 v5, 0xa

    invoke-direct {v4, v5}, Llyiahf/vczjk/pp3;-><init>(I)V

    const-string v5, "AppLabel"

    const/4 v6, 0x2

    invoke-direct {v2, v5, v6, v3, v4}, Llyiahf/vczjk/sw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/rw;)V

    new-instance v3, Llyiahf/vczjk/sw;

    sget v4, Lgithub/tornaco/android/thanos/res/R$string;->common_sort_by_install_time:I

    new-instance v5, Llyiahf/vczjk/qp3;

    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    const-string v6, "InstallTime"

    const/4 v7, 0x3

    invoke-direct {v3, v6, v7, v4, v5}, Llyiahf/vczjk/sw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/rw;)V

    new-instance v4, Llyiahf/vczjk/sw;

    sget v5, Lgithub/tornaco/android/thanos/res/R$string;->common_sort_by_update_time:I

    new-instance v6, Llyiahf/vczjk/rp3;

    const/16 v7, 0xa

    invoke-direct {v6, v7}, Llyiahf/vczjk/rp3;-><init>(I)V

    const-string v7, "UpdateTime"

    const/4 v8, 0x4

    invoke-direct {v4, v7, v8, v5, v6}, Llyiahf/vczjk/sw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/rw;)V

    new-instance v5, Llyiahf/vczjk/sw;

    sget v6, Lgithub/tornaco/android/thanos/res/R$string;->common_sort_by_last_used_time:I

    new-instance v7, Llyiahf/vczjk/sp3;

    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    const-string v8, "LastUsedTime"

    const/4 v9, 0x5

    invoke-direct {v5, v8, v9, v6, v7}, Llyiahf/vczjk/sw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/rw;)V

    sput-object v5, Llyiahf/vczjk/sw;->OooOOO:Llyiahf/vczjk/sw;

    new-instance v6, Llyiahf/vczjk/sw;

    sget v7, Lgithub/tornaco/android/thanos/res/R$string;->common_sort_by_total_used_time:I

    new-instance v8, Llyiahf/vczjk/tp3;

    const/16 v9, 0xa

    invoke-direct {v8, v9}, Llyiahf/vczjk/tp3;-><init>(I)V

    const-string v9, "TotalUsedTime"

    const/4 v10, 0x6

    invoke-direct {v6, v9, v10, v7, v8}, Llyiahf/vczjk/sw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/rw;)V

    sput-object v6, Llyiahf/vczjk/sw;->OooOOOO:Llyiahf/vczjk/sw;

    new-instance v7, Llyiahf/vczjk/sw;

    sget v8, Lgithub/tornaco/android/thanos/res/R$string;->common_sort_by_install_sdk_version:I

    new-instance v9, Llyiahf/vczjk/up3;

    const/16 v10, 0xa

    invoke-direct {v9, v10}, Llyiahf/vczjk/up3;-><init>(I)V

    const-string v10, "SdkVersion"

    const/4 v11, 0x7

    invoke-direct {v7, v10, v11, v8, v9}, Llyiahf/vczjk/sw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/rw;)V

    new-instance v8, Llyiahf/vczjk/sw;

    sget v9, Lgithub/tornaco/android/thanos/res/R$string;->common_sort_by_install_apk_size:I

    new-instance v10, Llyiahf/vczjk/vp3;

    const/16 v11, 0xa

    invoke-direct {v10, v11}, Llyiahf/vczjk/vp3;-><init>(I)V

    const-string v11, "ApkSize"

    const/16 v12, 0x8

    invoke-direct {v8, v11, v12, v9, v10}, Llyiahf/vczjk/sw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/rw;)V

    new-instance v9, Llyiahf/vczjk/sw;

    sget v10, Lgithub/tornaco/android/thanos/res/R$string;->common_sort_by_install_app_uid:I

    new-instance v11, Llyiahf/vczjk/xj0;

    const/16 v12, 0xa

    invoke-direct {v11, v12}, Llyiahf/vczjk/xj0;-><init>(I)V

    const-string v12, "AppUid"

    const/16 v13, 0x9

    invoke-direct {v9, v12, v13, v10, v11}, Llyiahf/vczjk/sw;-><init>(Ljava/lang/String;IILlyiahf/vczjk/rw;)V

    filled-new-array/range {v0 .. v9}, [Llyiahf/vczjk/sw;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/sw;->OooOOOo:[Llyiahf/vczjk/sw;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;IILlyiahf/vczjk/rw;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    iput p3, p0, Llyiahf/vczjk/sw;->labelRes:I

    iput-object p4, p0, Llyiahf/vczjk/sw;->provider:Llyiahf/vczjk/rw;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/sw;
    .locals 1

    const-class v0, Llyiahf/vczjk/sw;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/sw;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/sw;
    .locals 1

    sget-object v0, Llyiahf/vczjk/sw;->OooOOOo:[Llyiahf/vczjk/sw;

    invoke-virtual {v0}, [Llyiahf/vczjk/sw;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/sw;

    return-object v0
.end method
