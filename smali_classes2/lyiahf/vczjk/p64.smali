.class public abstract Llyiahf/vczjk/p64;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/hc3;

.field public static final OooO0O0:[Llyiahf/vczjk/hc3;

.field public static final OooO0OO:Llyiahf/vczjk/era;

.field public static final OooO0Oo:Llyiahf/vczjk/q64;


# direct methods
.method static constructor <clinit>()V
    .locals 26

    new-instance v0, Llyiahf/vczjk/hc3;

    const-string v1, "org.jspecify.nullness"

    invoke-direct {v0, v1}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/hc3;

    const-string v2, "org.jspecify.annotations"

    invoke-direct {v1, v2}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    sput-object v1, Llyiahf/vczjk/p64;->OooO00o:Llyiahf/vczjk/hc3;

    new-instance v2, Llyiahf/vczjk/hc3;

    const-string v3, "io.reactivex.rxjava3.annotations"

    invoke-direct {v2, v3}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance v3, Llyiahf/vczjk/hc3;

    const-string v4, "org.checkerframework.checker.nullness.compatqual"

    invoke-direct {v3, v4}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    iget-object v4, v2, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    iget-object v4, v4, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    new-instance v5, Llyiahf/vczjk/hc3;

    const-string v6, ".Nullable"

    invoke-static {v4, v6}, Llyiahf/vczjk/u81;->OooOO0o(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    invoke-direct {v5, v6}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance v6, Llyiahf/vczjk/hc3;

    const-string v7, ".NonNull"

    invoke-static {v4, v7}, Llyiahf/vczjk/u81;->OooOO0o(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    invoke-direct {v6, v4}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    filled-new-array {v5, v6}, [Llyiahf/vczjk/hc3;

    move-result-object v4

    sput-object v4, Llyiahf/vczjk/p64;->OooO0O0:[Llyiahf/vczjk/hc3;

    new-instance v4, Llyiahf/vczjk/era;

    new-instance v5, Llyiahf/vczjk/hc3;

    const-string v6, "org.jetbrains.annotations"

    invoke-direct {v5, v6}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    sget-object v6, Llyiahf/vczjk/q64;->OooO0Oo:Llyiahf/vczjk/q64;

    new-instance v7, Llyiahf/vczjk/xn6;

    invoke-direct {v7, v5, v6}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance v5, Llyiahf/vczjk/hc3;

    const-string v8, "androidx.annotation"

    invoke-direct {v5, v8}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance v8, Llyiahf/vczjk/xn6;

    invoke-direct {v8, v5, v6}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance v5, Llyiahf/vczjk/hc3;

    const-string v9, "android.support.annotation"

    invoke-direct {v5, v9}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance v9, Llyiahf/vczjk/xn6;

    invoke-direct {v9, v5, v6}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance v5, Llyiahf/vczjk/hc3;

    const-string v10, "android.annotation"

    invoke-direct {v5, v10}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance v10, Llyiahf/vczjk/xn6;

    invoke-direct {v10, v5, v6}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance v5, Llyiahf/vczjk/hc3;

    const-string v11, "com.android.annotations"

    invoke-direct {v5, v11}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance v11, Llyiahf/vczjk/xn6;

    invoke-direct {v11, v5, v6}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance v5, Llyiahf/vczjk/hc3;

    const-string v12, "org.eclipse.jdt.annotation"

    invoke-direct {v5, v12}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance v12, Llyiahf/vczjk/xn6;

    invoke-direct {v12, v5, v6}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance v5, Llyiahf/vczjk/hc3;

    const-string v13, "org.checkerframework.checker.nullness.qual"

    invoke-direct {v5, v13}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance v13, Llyiahf/vczjk/xn6;

    invoke-direct {v13, v5, v6}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance v14, Llyiahf/vczjk/xn6;

    invoke-direct {v14, v3, v6}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance v3, Llyiahf/vczjk/hc3;

    const-string v5, "javax.annotation"

    invoke-direct {v3, v5}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance v15, Llyiahf/vczjk/xn6;

    invoke-direct {v15, v3, v6}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance v3, Llyiahf/vczjk/hc3;

    const-string v5, "edu.umd.cs.findbugs.annotations"

    invoke-direct {v3, v5}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance v5, Llyiahf/vczjk/xn6;

    invoke-direct {v5, v3, v6}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance v3, Llyiahf/vczjk/hc3;

    move-object/from16 v16, v5

    const-string v5, "io.reactivex.annotations"

    invoke-direct {v3, v5}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance v5, Llyiahf/vczjk/xn6;

    invoke-direct {v5, v3, v6}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance v3, Llyiahf/vczjk/hc3;

    move-object/from16 v17, v5

    const-string v5, "androidx.annotation.RecentlyNullable"

    invoke-direct {v3, v5}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance v5, Llyiahf/vczjk/q64;

    move-object/from16 v24, v4

    sget-object v4, Llyiahf/vczjk/yq7;->OooOOO:Llyiahf/vczjk/yq7;

    move-object/from16 v18, v7

    const/4 v7, 0x4

    invoke-direct {v5, v4, v7}, Llyiahf/vczjk/q64;-><init>(Llyiahf/vczjk/yq7;I)V

    new-instance v7, Llyiahf/vczjk/xn6;

    invoke-direct {v7, v3, v5}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance v3, Llyiahf/vczjk/hc3;

    const-string v5, "androidx.annotation.RecentlyNonNull"

    invoke-direct {v3, v5}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance v5, Llyiahf/vczjk/q64;

    move-object/from16 v20, v7

    const/4 v7, 0x4

    invoke-direct {v5, v4, v7}, Llyiahf/vczjk/q64;-><init>(Llyiahf/vczjk/yq7;I)V

    new-instance v7, Llyiahf/vczjk/xn6;

    invoke-direct {v7, v3, v5}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance v3, Llyiahf/vczjk/hc3;

    const-string v5, "lombok"

    invoke-direct {v3, v5}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance v5, Llyiahf/vczjk/xn6;

    invoke-direct {v5, v3, v6}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance v3, Llyiahf/vczjk/q64;

    new-instance v6, Llyiahf/vczjk/bl4;

    move-object/from16 v21, v5

    const/4 v5, 0x2

    move-object/from16 v22, v7

    const/4 v7, 0x1

    move-object/from16 v23, v8

    const/4 v8, 0x0

    invoke-direct {v6, v5, v7, v8}, Llyiahf/vczjk/bl4;-><init>(III)V

    sget-object v5, Llyiahf/vczjk/yq7;->OooOOOO:Llyiahf/vczjk/yq7;

    invoke-direct {v3, v4, v6, v5}, Llyiahf/vczjk/q64;-><init>(Llyiahf/vczjk/yq7;Llyiahf/vczjk/bl4;Llyiahf/vczjk/yq7;)V

    new-instance v6, Llyiahf/vczjk/xn6;

    invoke-direct {v6, v0, v3}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance v0, Llyiahf/vczjk/q64;

    new-instance v3, Llyiahf/vczjk/bl4;

    move-object/from16 v25, v6

    const/4 v6, 0x2

    invoke-direct {v3, v6, v7, v8}, Llyiahf/vczjk/bl4;-><init>(III)V

    invoke-direct {v0, v4, v3, v5}, Llyiahf/vczjk/q64;-><init>(Llyiahf/vczjk/yq7;Llyiahf/vczjk/bl4;Llyiahf/vczjk/yq7;)V

    new-instance v3, Llyiahf/vczjk/xn6;

    invoke-direct {v3, v1, v0}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance v0, Llyiahf/vczjk/q64;

    new-instance v1, Llyiahf/vczjk/bl4;

    const/16 v6, 0x8

    invoke-direct {v1, v7, v6, v8}, Llyiahf/vczjk/bl4;-><init>(III)V

    invoke-direct {v0, v4, v1, v5}, Llyiahf/vczjk/q64;-><init>(Llyiahf/vczjk/yq7;Llyiahf/vczjk/bl4;Llyiahf/vczjk/yq7;)V

    new-instance v1, Llyiahf/vczjk/xn6;

    invoke-direct {v1, v2, v0}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    move-object/from16 v7, v18

    move-object/from16 v18, v20

    move-object/from16 v20, v21

    move-object/from16 v19, v22

    move-object/from16 v8, v23

    move-object/from16 v21, v25

    const/4 v0, 0x4

    move-object/from16 v23, v1

    move-object/from16 v22, v3

    filled-new-array/range {v7 .. v23}, [Llyiahf/vczjk/xn6;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/lc5;->o0ooOO0([Llyiahf/vczjk/xn6;)Ljava/util/Map;

    move-result-object v1

    move-object/from16 v2, v24

    invoke-direct {v2, v1}, Llyiahf/vczjk/era;-><init>(Ljava/util/Map;)V

    sput-object v2, Llyiahf/vczjk/p64;->OooO0OO:Llyiahf/vczjk/era;

    new-instance v1, Llyiahf/vczjk/q64;

    invoke-direct {v1, v4, v0}, Llyiahf/vczjk/q64;-><init>(Llyiahf/vczjk/yq7;I)V

    sput-object v1, Llyiahf/vczjk/p64;->OooO0Oo:Llyiahf/vczjk/q64;

    return-void
.end method
