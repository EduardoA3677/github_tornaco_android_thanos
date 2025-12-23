.class public final Llyiahf/vczjk/tc7;
.super Llyiahf/vczjk/sg3;
.source "SourceFile"


# static fields
.field public static final OooOOO:Llyiahf/vczjk/je4;

.field public static final OooOOO0:Llyiahf/vczjk/tc7;


# instance fields
.field private bitField0_:I

.field private function_:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/pc7;",
            ">;"
        }
    .end annotation
.end field

.field private memoizedIsInitialized:B

.field private memoizedSerializedSize:I

.field private property_:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/xc7;",
            ">;"
        }
    .end annotation
.end field

.field private typeAlias_:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/jd7;",
            ">;"
        }
    .end annotation
.end field

.field private typeTable_:Llyiahf/vczjk/nd7;

.field private final unknownFields:Llyiahf/vczjk/im0;

.field private versionRequirementTable_:Llyiahf/vczjk/ud7;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/je4;

    const/16 v1, 0x10

    invoke-direct {v0, v1}, Llyiahf/vczjk/je4;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/tc7;->OooOOO:Llyiahf/vczjk/je4;

    new-instance v0, Llyiahf/vczjk/tc7;

    invoke-direct {v0}, Llyiahf/vczjk/tc7;-><init>()V

    sput-object v0, Llyiahf/vczjk/tc7;->OooOOO0:Llyiahf/vczjk/tc7;

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/tc7;->function_:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/tc7;->property_:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/tc7;->typeAlias_:Ljava/util/List;

    sget-object v1, Llyiahf/vczjk/nd7;->OooOOO0:Llyiahf/vczjk/nd7;

    iput-object v1, v0, Llyiahf/vczjk/tc7;->typeTable_:Llyiahf/vczjk/nd7;

    sget-object v1, Llyiahf/vczjk/ud7;->OooOOO0:Llyiahf/vczjk/ud7;

    iput-object v1, v0, Llyiahf/vczjk/tc7;->versionRequirementTable_:Llyiahf/vczjk/ud7;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/sg3;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/tc7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/tc7;->memoizedSerializedSize:I

    sget-object v0, Llyiahf/vczjk/im0;->OooOOO0:Llyiahf/vczjk/h25;

    iput-object v0, p0, Llyiahf/vczjk/tc7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    .locals 10

    invoke-direct {p0}, Llyiahf/vczjk/sg3;-><init>()V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/tc7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/tc7;->memoizedSerializedSize:I

    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v0, p0, Llyiahf/vczjk/tc7;->function_:Ljava/util/List;

    iput-object v0, p0, Llyiahf/vczjk/tc7;->property_:Ljava/util/List;

    iput-object v0, p0, Llyiahf/vczjk/tc7;->typeAlias_:Ljava/util/List;

    sget-object v0, Llyiahf/vczjk/nd7;->OooOOO0:Llyiahf/vczjk/nd7;

    iput-object v0, p0, Llyiahf/vczjk/tc7;->typeTable_:Llyiahf/vczjk/nd7;

    sget-object v0, Llyiahf/vczjk/ud7;->OooOOO0:Llyiahf/vczjk/ud7;

    iput-object v0, p0, Llyiahf/vczjk/tc7;->versionRequirementTable_:Llyiahf/vczjk/ud7;

    new-instance v0, Llyiahf/vczjk/hm0;

    invoke-direct {v0}, Llyiahf/vczjk/hm0;-><init>()V

    const/4 v1, 0x1

    invoke-static {v0, v1}, Llyiahf/vczjk/n11;->OooOo0(Ljava/io/OutputStream;I)Llyiahf/vczjk/n11;

    move-result-object v2

    const/4 v3, 0x0

    move v4, v3

    :cond_0
    :goto_0
    const/4 v5, 0x4

    const/4 v6, 0x2

    if-nez v3, :cond_11

    :try_start_0
    invoke-virtual {p1}, Llyiahf/vczjk/h11;->OooOOO()I

    move-result v7

    if-eqz v7, :cond_1

    const/16 v8, 0x1a

    if-eq v7, v8, :cond_c

    const/16 v8, 0x22

    if-eq v7, v8, :cond_a

    const/16 v8, 0x2a

    if-eq v7, v8, :cond_8

    const/16 v8, 0xf2

    const/4 v9, 0x0

    if-eq v7, v8, :cond_5

    const/16 v8, 0x102

    if-eq v7, v8, :cond_2

    invoke-virtual {p0, p1, v2, p2, v7}, Llyiahf/vczjk/sg3;->OooOO0o(Llyiahf/vczjk/h11;Llyiahf/vczjk/n11;Llyiahf/vczjk/iu2;I)Z

    move-result v5

    if-nez v5, :cond_0

    :cond_1
    move v3, v1

    goto :goto_0

    :catchall_0
    move-exception p1

    goto/16 :goto_3

    :catch_0
    move-exception p1

    goto/16 :goto_1

    :catch_1
    move-exception p1

    goto/16 :goto_2

    :cond_2
    iget v7, p0, Llyiahf/vczjk/tc7;->bitField0_:I

    and-int/2addr v7, v6

    if-ne v7, v6, :cond_3

    iget-object v7, p0, Llyiahf/vczjk/tc7;->versionRequirementTable_:Llyiahf/vczjk/ud7;

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v9, Llyiahf/vczjk/dc7;

    const/4 v8, 0x2

    invoke-direct {v9, v8}, Llyiahf/vczjk/dc7;-><init>(I)V

    sget-object v8, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v8, v9, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-virtual {v9, v7}, Llyiahf/vczjk/dc7;->OooOOO0(Llyiahf/vczjk/ud7;)V

    :cond_3
    sget-object v7, Llyiahf/vczjk/ud7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {p1, v7, p2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/ud7;

    iput-object v7, p0, Llyiahf/vczjk/tc7;->versionRequirementTable_:Llyiahf/vczjk/ud7;

    if-eqz v9, :cond_4

    invoke-virtual {v9, v7}, Llyiahf/vczjk/dc7;->OooOOO0(Llyiahf/vczjk/ud7;)V

    invoke-virtual {v9}, Llyiahf/vczjk/dc7;->OooO()Llyiahf/vczjk/ud7;

    move-result-object v7

    iput-object v7, p0, Llyiahf/vczjk/tc7;->versionRequirementTable_:Llyiahf/vczjk/ud7;

    :cond_4
    iget v7, p0, Llyiahf/vczjk/tc7;->bitField0_:I

    or-int/2addr v7, v6

    iput v7, p0, Llyiahf/vczjk/tc7;->bitField0_:I

    goto :goto_0

    :cond_5
    iget v7, p0, Llyiahf/vczjk/tc7;->bitField0_:I

    and-int/2addr v7, v1

    if-ne v7, v1, :cond_6

    iget-object v7, p0, Llyiahf/vczjk/tc7;->typeTable_:Llyiahf/vczjk/nd7;

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v7}, Llyiahf/vczjk/nd7;->OooOO0o(Llyiahf/vczjk/nd7;)Llyiahf/vczjk/vb7;

    move-result-object v9

    :cond_6
    sget-object v7, Llyiahf/vczjk/nd7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {p1, v7, p2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/nd7;

    iput-object v7, p0, Llyiahf/vczjk/tc7;->typeTable_:Llyiahf/vczjk/nd7;

    if-eqz v9, :cond_7

    invoke-virtual {v9, v7}, Llyiahf/vczjk/vb7;->OooOO0(Llyiahf/vczjk/nd7;)V

    invoke-virtual {v9}, Llyiahf/vczjk/vb7;->OooO0oO()Llyiahf/vczjk/nd7;

    move-result-object v7

    iput-object v7, p0, Llyiahf/vczjk/tc7;->typeTable_:Llyiahf/vczjk/nd7;

    :cond_7
    iget v7, p0, Llyiahf/vczjk/tc7;->bitField0_:I

    or-int/2addr v7, v1

    iput v7, p0, Llyiahf/vczjk/tc7;->bitField0_:I

    goto/16 :goto_0

    :cond_8
    and-int/lit8 v7, v4, 0x4

    if-eq v7, v5, :cond_9

    new-instance v7, Ljava/util/ArrayList;

    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    iput-object v7, p0, Llyiahf/vczjk/tc7;->typeAlias_:Ljava/util/List;

    or-int/lit8 v4, v4, 0x4

    :cond_9
    iget-object v7, p0, Llyiahf/vczjk/tc7;->typeAlias_:Ljava/util/List;

    sget-object v8, Llyiahf/vczjk/jd7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {p1, v8, p2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v8

    invoke-interface {v7, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto/16 :goto_0

    :cond_a
    and-int/lit8 v7, v4, 0x2

    if-eq v7, v6, :cond_b

    new-instance v7, Ljava/util/ArrayList;

    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    iput-object v7, p0, Llyiahf/vczjk/tc7;->property_:Ljava/util/List;

    or-int/lit8 v4, v4, 0x2

    :cond_b
    iget-object v7, p0, Llyiahf/vczjk/tc7;->property_:Ljava/util/List;

    sget-object v8, Llyiahf/vczjk/xc7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {p1, v8, p2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v8

    invoke-interface {v7, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto/16 :goto_0

    :cond_c
    and-int/lit8 v7, v4, 0x1

    if-eq v7, v1, :cond_d

    new-instance v7, Ljava/util/ArrayList;

    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    iput-object v7, p0, Llyiahf/vczjk/tc7;->function_:Ljava/util/List;

    or-int/lit8 v4, v4, 0x1

    :cond_d
    iget-object v7, p0, Llyiahf/vczjk/tc7;->function_:Ljava/util/List;

    sget-object v8, Llyiahf/vczjk/pc7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {p1, v8, p2}, Llyiahf/vczjk/h11;->OooO0oO(Llyiahf/vczjk/kp6;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v8

    invoke-interface {v7, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto/16 :goto_0

    :goto_1
    :try_start_1
    new-instance p2, Llyiahf/vczjk/i44;

    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Llyiahf/vczjk/i44;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p0}, Llyiahf/vczjk/i44;->OooO0O0(Llyiahf/vczjk/pi5;)V

    throw p2

    :goto_2
    invoke-virtual {p1, p0}, Llyiahf/vczjk/i44;->OooO0O0(Llyiahf/vczjk/pi5;)V

    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :goto_3
    and-int/lit8 p2, v4, 0x1

    if-ne p2, v1, :cond_e

    iget-object p2, p0, Llyiahf/vczjk/tc7;->function_:Ljava/util/List;

    invoke-static {p2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/tc7;->function_:Ljava/util/List;

    :cond_e
    and-int/lit8 p2, v4, 0x2

    if-ne p2, v6, :cond_f

    iget-object p2, p0, Llyiahf/vczjk/tc7;->property_:Ljava/util/List;

    invoke-static {p2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/tc7;->property_:Ljava/util/List;

    :cond_f
    and-int/lit8 p2, v4, 0x4

    if-ne p2, v5, :cond_10

    iget-object p2, p0, Llyiahf/vczjk/tc7;->typeAlias_:Ljava/util/List;

    invoke-static {p2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/tc7;->typeAlias_:Ljava/util/List;

    :cond_10
    :try_start_2
    invoke-virtual {v2}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    :catch_2
    invoke-virtual {v0}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/tc7;->unknownFields:Llyiahf/vczjk/im0;

    goto :goto_4

    :catchall_1
    move-exception p1

    invoke-virtual {v0}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/tc7;->unknownFields:Llyiahf/vczjk/im0;

    throw p1

    :goto_4
    invoke-virtual {p0}, Llyiahf/vczjk/sg3;->OooOO0O()V

    throw p1

    :cond_11
    and-int/lit8 p1, v4, 0x1

    if-ne p1, v1, :cond_12

    iget-object p1, p0, Llyiahf/vczjk/tc7;->function_:Ljava/util/List;

    invoke-static {p1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/tc7;->function_:Ljava/util/List;

    :cond_12
    and-int/lit8 p1, v4, 0x2

    if-ne p1, v6, :cond_13

    iget-object p1, p0, Llyiahf/vczjk/tc7;->property_:Ljava/util/List;

    invoke-static {p1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/tc7;->property_:Ljava/util/List;

    :cond_13
    and-int/lit8 p1, v4, 0x4

    if-ne p1, v5, :cond_14

    iget-object p1, p0, Llyiahf/vczjk/tc7;->typeAlias_:Ljava/util/List;

    invoke-static {p1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/tc7;->typeAlias_:Ljava/util/List;

    :cond_14
    :try_start_3
    invoke-virtual {v2}, Llyiahf/vczjk/n11;->OooOO0o()V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    :catch_3
    invoke-virtual {v0}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/tc7;->unknownFields:Llyiahf/vczjk/im0;

    goto :goto_5

    :catchall_2
    move-exception p1

    invoke-virtual {v0}, Llyiahf/vczjk/hm0;->OooOOOO()Llyiahf/vczjk/im0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/tc7;->unknownFields:Llyiahf/vczjk/im0;

    throw p1

    :goto_5
    invoke-virtual {p0}, Llyiahf/vczjk/sg3;->OooOO0O()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/sc7;)V
    .locals 1

    invoke-direct {p0, p1}, Llyiahf/vczjk/sg3;-><init>(Llyiahf/vczjk/rg3;)V

    const/4 v0, -0x1

    iput-byte v0, p0, Llyiahf/vczjk/tc7;->memoizedIsInitialized:B

    iput v0, p0, Llyiahf/vczjk/tc7;->memoizedSerializedSize:I

    iget-object p1, p1, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    iput-object p1, p0, Llyiahf/vczjk/tc7;->unknownFields:Llyiahf/vczjk/im0;

    return-void
.end method

.method public static synthetic OooOOO(Llyiahf/vczjk/tc7;)Ljava/util/List;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/tc7;->function_:Ljava/util/List;

    return-object p0
.end method

.method public static synthetic OooOOOO(Llyiahf/vczjk/tc7;Ljava/util/List;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/tc7;->function_:Ljava/util/List;

    return-void
.end method

.method public static synthetic OooOOOo(Llyiahf/vczjk/tc7;)Ljava/util/List;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/tc7;->property_:Ljava/util/List;

    return-object p0
.end method

.method public static synthetic OooOOo(Llyiahf/vczjk/tc7;)Ljava/util/List;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/tc7;->typeAlias_:Ljava/util/List;

    return-object p0
.end method

.method public static synthetic OooOOo0(Llyiahf/vczjk/tc7;Ljava/util/List;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/tc7;->property_:Ljava/util/List;

    return-void
.end method

.method public static synthetic OooOOoo(Llyiahf/vczjk/tc7;Ljava/util/List;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/tc7;->typeAlias_:Ljava/util/List;

    return-void
.end method

.method public static synthetic OooOo0(Llyiahf/vczjk/tc7;Llyiahf/vczjk/ud7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/tc7;->versionRequirementTable_:Llyiahf/vczjk/ud7;

    return-void
.end method

.method public static synthetic OooOo00(Llyiahf/vczjk/tc7;Llyiahf/vczjk/nd7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/tc7;->typeTable_:Llyiahf/vczjk/nd7;

    return-void
.end method

.method public static synthetic OooOo0O(Llyiahf/vczjk/tc7;I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/tc7;->bitField0_:I

    return-void
.end method

.method public static synthetic OooOo0o(Llyiahf/vczjk/tc7;)Llyiahf/vczjk/im0;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/tc7;->unknownFields:Llyiahf/vczjk/im0;

    return-object p0
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/n11;)V
    .locals 5

    invoke-virtual {p0}, Llyiahf/vczjk/tc7;->getSerializedSize()I

    new-instance v0, Llyiahf/vczjk/n62;

    invoke-direct {v0, p0}, Llyiahf/vczjk/n62;-><init>(Llyiahf/vczjk/sg3;)V

    const/4 v1, 0x0

    move v2, v1

    :goto_0
    iget-object v3, p0, Llyiahf/vczjk/tc7;->function_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v2, v3, :cond_0

    iget-object v3, p0, Llyiahf/vczjk/tc7;->function_:Ljava/util/List;

    invoke-interface {v3, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/pi5;

    const/4 v4, 0x3

    invoke-virtual {p1, v4, v3}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_0
    move v2, v1

    :goto_1
    iget-object v3, p0, Llyiahf/vczjk/tc7;->property_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v2, v3, :cond_1

    iget-object v3, p0, Llyiahf/vczjk/tc7;->property_:Ljava/util/List;

    invoke-interface {v3, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/pi5;

    const/4 v4, 0x4

    invoke-virtual {p1, v4, v3}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    add-int/lit8 v2, v2, 0x1

    goto :goto_1

    :cond_1
    :goto_2
    iget-object v2, p0, Llyiahf/vczjk/tc7;->typeAlias_:Ljava/util/List;

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v2

    if-ge v1, v2, :cond_2

    iget-object v2, p0, Llyiahf/vczjk/tc7;->typeAlias_:Ljava/util/List;

    invoke-interface {v2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/pi5;

    const/4 v3, 0x5

    invoke-virtual {p1, v3, v2}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_2

    :cond_2
    iget v1, p0, Llyiahf/vczjk/tc7;->bitField0_:I

    const/4 v2, 0x1

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_3

    const/16 v1, 0x1e

    iget-object v2, p0, Llyiahf/vczjk/tc7;->typeTable_:Llyiahf/vczjk/nd7;

    invoke-virtual {p1, v1, v2}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    :cond_3
    iget v1, p0, Llyiahf/vczjk/tc7;->bitField0_:I

    const/4 v2, 0x2

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_4

    const/16 v1, 0x20

    iget-object v2, p0, Llyiahf/vczjk/tc7;->versionRequirementTable_:Llyiahf/vczjk/ud7;

    invoke-virtual {p1, v1, v2}, Llyiahf/vczjk/n11;->OooOoo(ILlyiahf/vczjk/pi5;)V

    :cond_4
    const/16 v1, 0xc8

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/n62;->o000OO(ILlyiahf/vczjk/n11;)V

    iget-object v0, p0, Llyiahf/vczjk/tc7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/n11;->Oooo000(Llyiahf/vczjk/im0;)V

    return-void
.end method

.method public final OooOo()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tc7;->function_:Ljava/util/List;

    return-object v0
.end method

.method public final OooOoO()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tc7;->typeAlias_:Ljava/util/List;

    return-object v0
.end method

.method public final OooOoO0()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tc7;->property_:Ljava/util/List;

    return-object v0
.end method

.method public final OooOoOO()Llyiahf/vczjk/nd7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tc7;->typeTable_:Llyiahf/vczjk/nd7;

    return-object v0
.end method

.method public final OooOoo()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/tc7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    return v1

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOoo0()Llyiahf/vczjk/ud7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tc7;->versionRequirementTable_:Llyiahf/vczjk/ud7;

    return-object v0
.end method

.method public final OooOooO()Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/tc7;->bitField0_:I

    const/4 v1, 0x2

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final getDefaultInstanceForType()Llyiahf/vczjk/pi5;
    .locals 1

    sget-object v0, Llyiahf/vczjk/tc7;->OooOOO0:Llyiahf/vczjk/tc7;

    return-object v0
.end method

.method public final getSerializedSize()I
    .locals 5

    iget v0, p0, Llyiahf/vczjk/tc7;->memoizedSerializedSize:I

    const/4 v1, -0x1

    if-eq v0, v1, :cond_0

    return v0

    :cond_0
    const/4 v0, 0x0

    move v1, v0

    move v2, v1

    :goto_0
    iget-object v3, p0, Llyiahf/vczjk/tc7;->function_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v1, v3, :cond_1

    iget-object v3, p0, Llyiahf/vczjk/tc7;->function_:Ljava/util/List;

    invoke-interface {v3, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/pi5;

    const/4 v4, 0x3

    invoke-static {v4, v3}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v3

    add-int/2addr v2, v3

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    move v1, v0

    :goto_1
    iget-object v3, p0, Llyiahf/vczjk/tc7;->property_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v1, v3, :cond_2

    iget-object v3, p0, Llyiahf/vczjk/tc7;->property_:Ljava/util/List;

    invoke-interface {v3, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/pi5;

    const/4 v4, 0x4

    invoke-static {v4, v3}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v3

    add-int/2addr v2, v3

    add-int/lit8 v1, v1, 0x1

    goto :goto_1

    :cond_2
    :goto_2
    iget-object v1, p0, Llyiahf/vczjk/tc7;->typeAlias_:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    if-ge v0, v1, :cond_3

    iget-object v1, p0, Llyiahf/vczjk/tc7;->typeAlias_:Ljava/util/List;

    invoke-interface {v1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/pi5;

    const/4 v3, 0x5

    invoke-static {v3, v1}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v1

    add-int/2addr v2, v1

    add-int/lit8 v0, v0, 0x1

    goto :goto_2

    :cond_3
    iget v0, p0, Llyiahf/vczjk/tc7;->bitField0_:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_4

    const/16 v0, 0x1e

    iget-object v1, p0, Llyiahf/vczjk/tc7;->typeTable_:Llyiahf/vczjk/nd7;

    invoke-static {v0, v1}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v0

    add-int/2addr v2, v0

    :cond_4
    iget v0, p0, Llyiahf/vczjk/tc7;->bitField0_:I

    const/4 v1, 0x2

    and-int/2addr v0, v1

    if-ne v0, v1, :cond_5

    const/16 v0, 0x20

    iget-object v1, p0, Llyiahf/vczjk/tc7;->versionRequirementTable_:Llyiahf/vczjk/ud7;

    invoke-static {v0, v1}, Llyiahf/vczjk/n11;->OooO0oO(ILlyiahf/vczjk/pi5;)I

    move-result v0

    add-int/2addr v2, v0

    :cond_5
    invoke-virtual {p0}, Llyiahf/vczjk/sg3;->OooO0o()I

    move-result v0

    add-int/2addr v0, v2

    iget-object v1, p0, Llyiahf/vczjk/tc7;->unknownFields:Llyiahf/vczjk/im0;

    invoke-virtual {v1}, Llyiahf/vczjk/im0;->size()I

    move-result v1

    add-int/2addr v1, v0

    iput v1, p0, Llyiahf/vczjk/tc7;->memoizedSerializedSize:I

    return v1
.end method

.method public final isInitialized()Z
    .locals 4

    iget-byte v0, p0, Llyiahf/vczjk/tc7;->memoizedIsInitialized:B

    const/4 v1, 0x1

    if-ne v0, v1, :cond_0

    return v1

    :cond_0
    const/4 v2, 0x0

    if-nez v0, :cond_1

    return v2

    :cond_1
    move v0, v2

    :goto_0
    iget-object v3, p0, Llyiahf/vczjk/tc7;->function_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v0, v3, :cond_3

    iget-object v3, p0, Llyiahf/vczjk/tc7;->function_:Ljava/util/List;

    invoke-interface {v3, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/pc7;

    invoke-virtual {v3}, Llyiahf/vczjk/pc7;->isInitialized()Z

    move-result v3

    if-nez v3, :cond_2

    iput-byte v2, p0, Llyiahf/vczjk/tc7;->memoizedIsInitialized:B

    return v2

    :cond_2
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_3
    move v0, v2

    :goto_1
    iget-object v3, p0, Llyiahf/vczjk/tc7;->property_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v0, v3, :cond_5

    iget-object v3, p0, Llyiahf/vczjk/tc7;->property_:Ljava/util/List;

    invoke-interface {v3, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/xc7;

    invoke-virtual {v3}, Llyiahf/vczjk/xc7;->isInitialized()Z

    move-result v3

    if-nez v3, :cond_4

    iput-byte v2, p0, Llyiahf/vczjk/tc7;->memoizedIsInitialized:B

    return v2

    :cond_4
    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    :cond_5
    move v0, v2

    :goto_2
    iget-object v3, p0, Llyiahf/vczjk/tc7;->typeAlias_:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v0, v3, :cond_7

    iget-object v3, p0, Llyiahf/vczjk/tc7;->typeAlias_:Ljava/util/List;

    invoke-interface {v3, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/jd7;

    invoke-virtual {v3}, Llyiahf/vczjk/jd7;->isInitialized()Z

    move-result v3

    if-nez v3, :cond_6

    iput-byte v2, p0, Llyiahf/vczjk/tc7;->memoizedIsInitialized:B

    return v2

    :cond_6
    add-int/lit8 v0, v0, 0x1

    goto :goto_2

    :cond_7
    invoke-virtual {p0}, Llyiahf/vczjk/tc7;->OooOoo()Z

    move-result v0

    if-eqz v0, :cond_8

    iget-object v0, p0, Llyiahf/vczjk/tc7;->typeTable_:Llyiahf/vczjk/nd7;

    invoke-virtual {v0}, Llyiahf/vczjk/nd7;->isInitialized()Z

    move-result v0

    if-nez v0, :cond_8

    iput-byte v2, p0, Llyiahf/vczjk/tc7;->memoizedIsInitialized:B

    return v2

    :cond_8
    invoke-virtual {p0}, Llyiahf/vczjk/sg3;->OooO0o0()Z

    move-result v0

    if-nez v0, :cond_9

    iput-byte v2, p0, Llyiahf/vczjk/tc7;->memoizedIsInitialized:B

    return v2

    :cond_9
    iput-byte v1, p0, Llyiahf/vczjk/tc7;->memoizedIsInitialized:B

    return v1
.end method

.method public final newBuilderForType()Llyiahf/vczjk/og3;
    .locals 1

    invoke-static {}, Llyiahf/vczjk/sc7;->OooO0oo()Llyiahf/vczjk/sc7;

    move-result-object v0

    return-object v0
.end method

.method public final toBuilder()Llyiahf/vczjk/og3;
    .locals 1

    invoke-static {}, Llyiahf/vczjk/sc7;->OooO0oo()Llyiahf/vczjk/sc7;

    move-result-object v0

    invoke-virtual {v0, p0}, Llyiahf/vczjk/sc7;->OooO(Llyiahf/vczjk/tc7;)V

    return-object v0
.end method
