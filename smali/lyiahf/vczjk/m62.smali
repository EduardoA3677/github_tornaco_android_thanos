.class public final Llyiahf/vczjk/m62;
.super Llyiahf/vczjk/yd7;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0o0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ru7;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/m62;->OooO0o0:I

    invoke-direct {p0, p1}, Llyiahf/vczjk/yd7;-><init>(Llyiahf/vczjk/ru7;)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo()Ljava/lang/String;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/m62;->OooO0o0:I

    packed-switch v0, :pswitch_data_0

    const-string v0, "INSERT OR IGNORE INTO `WorkTag` (`tag`,`work_spec_id`) VALUES (?,?)"

    return-object v0

    :pswitch_0
    const-string v0, "INSERT OR IGNORE INTO `WorkSpec` (`id`,`state`,`worker_class_name`,`input_merger_class_name`,`input`,`output`,`initial_delay`,`interval_duration`,`flex_duration`,`run_attempt_count`,`backoff_policy`,`backoff_delay_duration`,`last_enqueue_time`,`minimum_retention_duration`,`schedule_requested_at`,`run_in_foreground`,`out_of_quota_policy`,`period_count`,`generation`,`next_schedule_time_override`,`next_schedule_time_override_generation`,`stop_reason`,`trace_tag`,`required_network_type`,`required_network_request`,`requires_charging`,`requires_device_idle`,`requires_battery_not_low`,`requires_storage_not_low`,`trigger_content_update_delay`,`trigger_max_content_delay`,`content_uri_triggers`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"

    return-object v0

    :pswitch_1
    const-string v0, "INSERT OR REPLACE INTO `WorkProgress` (`work_spec_id`,`progress`) VALUES (?,?)"

    return-object v0

    :pswitch_2
    const-string v0, "INSERT OR IGNORE INTO `WorkName` (`name`,`work_spec_id`) VALUES (?,?)"

    return-object v0

    :pswitch_3
    const-string v0, "INSERT OR REPLACE INTO `SystemIdInfo` (`work_spec_id`,`generation`,`system_id`) VALUES (?,?,?)"

    return-object v0

    :pswitch_4
    const-string v0, "INSERT OR REPLACE INTO `rules_table` (`_id`,`name`,`label`,`type`,`iconIndex`,`isRegexRule`,`regexName`) VALUES (?,?,?,?,?,?,?)"

    return-object v0

    :pswitch_5
    const-string v0, "INSERT OR REPLACE INTO `Preference` (`key`,`long_value`) VALUES (?,?)"

    return-object v0

    :pswitch_6
    const-string v0, "INSERT OR IGNORE INTO `Dependency` (`work_spec_id`,`prerequisite_id`) VALUES (?,?)"

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0oO(Llyiahf/vczjk/la9;Ljava/lang/Object;)V
    .locals 17

    move-object/from16 v0, p1

    const/16 v11, 0xa

    const/16 v14, 0x8

    const/4 v15, 0x7

    const/16 v12, 0x9

    const/4 v13, 0x6

    const/4 v1, 0x5

    const/4 v2, 0x4

    const/4 v3, 0x3

    const/4 v4, 0x2

    const/4 v5, 0x1

    move-object/from16 v6, p0

    iget v7, v6, Llyiahf/vczjk/m62;->OooO0o0:I

    packed-switch v7, :pswitch_data_0

    move-object/from16 v1, p2

    check-cast v1, Llyiahf/vczjk/dra;

    iget-object v2, v1, Llyiahf/vczjk/dra;->OooO00o:Ljava/lang/String;

    invoke-interface {v0, v5, v2}, Llyiahf/vczjk/ha9;->OooOOO0(ILjava/lang/String;)V

    iget-object v1, v1, Llyiahf/vczjk/dra;->OooO0O0:Ljava/lang/String;

    invoke-interface {v0, v4, v1}, Llyiahf/vczjk/ha9;->OooOOO0(ILjava/lang/String;)V

    return-void

    :pswitch_0
    move-object/from16 v7, p2

    check-cast v7, Llyiahf/vczjk/ara;

    iget-object v8, v7, Llyiahf/vczjk/ara;->OooO00o:Ljava/lang/String;

    invoke-interface {v0, v5, v8}, Llyiahf/vczjk/ha9;->OooOOO0(ILjava/lang/String;)V

    iget-object v8, v7, Llyiahf/vczjk/ara;->OooO0O0:Llyiahf/vczjk/lqa;

    invoke-static {v8}, Llyiahf/vczjk/dr6;->OooOo0O(Llyiahf/vczjk/lqa;)I

    move-result v8

    int-to-long v9, v8

    invoke-interface {v0, v4, v9, v10}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget-object v8, v7, Llyiahf/vczjk/ara;->OooO0OO:Ljava/lang/String;

    invoke-interface {v0, v3, v8}, Llyiahf/vczjk/ha9;->OooOOO0(ILjava/lang/String;)V

    iget-object v8, v7, Llyiahf/vczjk/ara;->OooO0Oo:Ljava/lang/String;

    invoke-interface {v0, v2, v8}, Llyiahf/vczjk/ha9;->OooOOO0(ILjava/lang/String;)V

    iget-object v8, v7, Llyiahf/vczjk/ara;->OooO0o0:Llyiahf/vczjk/mw1;

    sget-object v9, Llyiahf/vczjk/mw1;->OooO0O0:Llyiahf/vczjk/mw1;

    invoke-static {v8}, Llyiahf/vczjk/nqa;->OoooO0O(Llyiahf/vczjk/mw1;)[B

    move-result-object v8

    invoke-interface {v0, v1, v8}, Llyiahf/vczjk/ha9;->OoooO0(I[B)V

    iget-object v8, v7, Llyiahf/vczjk/ara;->OooO0o:Llyiahf/vczjk/mw1;

    invoke-static {v8}, Llyiahf/vczjk/nqa;->OoooO0O(Llyiahf/vczjk/mw1;)[B

    move-result-object v8

    invoke-interface {v0, v13, v8}, Llyiahf/vczjk/ha9;->OoooO0(I[B)V

    iget-wide v8, v7, Llyiahf/vczjk/ara;->OooO0oO:J

    invoke-interface {v0, v15, v8, v9}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget-wide v8, v7, Llyiahf/vczjk/ara;->OooO0oo:J

    invoke-interface {v0, v14, v8, v9}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget-wide v8, v7, Llyiahf/vczjk/ara;->OooO:J

    invoke-interface {v0, v12, v8, v9}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget v8, v7, Llyiahf/vczjk/ara;->OooOO0O:I

    int-to-long v8, v8

    invoke-interface {v0, v11, v8, v9}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget v8, v7, Llyiahf/vczjk/ara;->OooOO0o:I

    const-string v9, "backoffPolicy"

    invoke-static {v8, v9}, Llyiahf/vczjk/u81;->OooOOo(ILjava/lang/String;)V

    invoke-static {v8}, Llyiahf/vczjk/ix8;->OooOo(I)I

    move-result v8

    if-eqz v8, :cond_1

    if-ne v8, v5, :cond_0

    move v8, v5

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/k61;

    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    throw v0

    :cond_1
    const/4 v8, 0x0

    :goto_0
    int-to-long v8, v8

    const/16 v10, 0xb

    invoke-interface {v0, v10, v8, v9}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget-wide v8, v7, Llyiahf/vczjk/ara;->OooOOO0:J

    const/16 v10, 0xc

    invoke-interface {v0, v10, v8, v9}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget-wide v8, v7, Llyiahf/vczjk/ara;->OooOOO:J

    const/16 v10, 0xd

    invoke-interface {v0, v10, v8, v9}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget-wide v8, v7, Llyiahf/vczjk/ara;->OooOOOO:J

    const/16 v10, 0xe

    invoke-interface {v0, v10, v8, v9}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget-wide v8, v7, Llyiahf/vczjk/ara;->OooOOOo:J

    const/16 v10, 0xf

    invoke-interface {v0, v10, v8, v9}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget-boolean v8, v7, Llyiahf/vczjk/ara;->OooOOo0:Z

    int-to-long v8, v8

    const/16 v10, 0x10

    invoke-interface {v0, v10, v8, v9}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget v8, v7, Llyiahf/vczjk/ara;->OooOOo:I

    const-string v9, "policy"

    invoke-static {v8, v9}, Llyiahf/vczjk/u81;->OooOOo(ILjava/lang/String;)V

    invoke-static {v8}, Llyiahf/vczjk/ix8;->OooOo(I)I

    move-result v8

    if-eqz v8, :cond_3

    if-ne v8, v5, :cond_2

    move v8, v5

    goto :goto_1

    :cond_2
    new-instance v0, Llyiahf/vczjk/k61;

    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    throw v0

    :cond_3
    const/4 v8, 0x0

    :goto_1
    int-to-long v8, v8

    const/16 v10, 0x11

    invoke-interface {v0, v10, v8, v9}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget v8, v7, Llyiahf/vczjk/ara;->OooOOoo:I

    int-to-long v8, v8

    const/16 v10, 0x12

    invoke-interface {v0, v10, v8, v9}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget v8, v7, Llyiahf/vczjk/ara;->OooOo00:I

    int-to-long v8, v8

    const/16 v10, 0x13

    invoke-interface {v0, v10, v8, v9}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget-wide v8, v7, Llyiahf/vczjk/ara;->OooOo0:J

    const/16 v10, 0x14

    invoke-interface {v0, v10, v8, v9}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget v8, v7, Llyiahf/vczjk/ara;->OooOo0O:I

    int-to-long v8, v8

    const/16 v10, 0x15

    invoke-interface {v0, v10, v8, v9}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget v8, v7, Llyiahf/vczjk/ara;->OooOo0o:I

    int-to-long v8, v8

    const/16 v10, 0x16

    invoke-interface {v0, v10, v8, v9}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget-object v8, v7, Llyiahf/vczjk/ara;->OooOo:Ljava/lang/String;

    const/16 v9, 0x17

    if-nez v8, :cond_4

    invoke-interface {v0, v9}, Llyiahf/vczjk/ha9;->OooO0o0(I)V

    goto :goto_2

    :cond_4
    invoke-interface {v0, v9, v8}, Llyiahf/vczjk/ha9;->OooOOO0(ILjava/lang/String;)V

    :goto_2
    iget-object v7, v7, Llyiahf/vczjk/ara;->OooOO0:Llyiahf/vczjk/qk1;

    iget v8, v7, Llyiahf/vczjk/qk1;->OooO00o:I

    const-string v9, "networkType"

    invoke-static {v8, v9}, Llyiahf/vczjk/u81;->OooOOo(ILjava/lang/String;)V

    invoke-static {v8}, Llyiahf/vczjk/ix8;->OooOo(I)I

    move-result v9

    const/16 v10, 0x1e

    if-eqz v9, :cond_a

    if-eq v9, v5, :cond_9

    if-eq v9, v4, :cond_8

    if-eq v9, v3, :cond_7

    if-eq v9, v2, :cond_6

    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    if-lt v2, v10, :cond_5

    if-ne v8, v13, :cond_5

    goto :goto_3

    :cond_5
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Could not convert "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-static {v8}, Llyiahf/vczjk/ii5;->OooOo(I)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, " to int"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_6
    move v1, v2

    goto :goto_3

    :cond_7
    move v1, v3

    goto :goto_3

    :cond_8
    move v1, v4

    goto :goto_3

    :cond_9
    move v1, v5

    goto :goto_3

    :cond_a
    const/4 v1, 0x0

    :goto_3
    const/16 v2, 0x18

    int-to-long v3, v1

    invoke-interface {v0, v2, v3, v4}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    const-string v1, "requestCompat"

    iget-object v2, v7, Llyiahf/vczjk/qk1;->OooO0O0:Llyiahf/vczjk/c06;

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    const-string v3, "outputStream.toByteArray()"

    const/16 v4, 0x1f

    const/16 v8, 0x1c

    if-ge v1, v8, :cond_b

    const/4 v9, 0x0

    new-array v1, v9, [B

    goto/16 :goto_a

    :cond_b
    const/4 v9, 0x0

    iget-object v2, v2, Llyiahf/vczjk/c06;->OooO00o:Landroid/net/NetworkRequest;

    if-nez v2, :cond_c

    new-array v1, v9, [B

    goto/16 :goto_a

    :cond_c
    new-instance v9, Ljava/io/ByteArrayOutputStream;

    invoke-direct {v9}, Ljava/io/ByteArrayOutputStream;-><init>()V

    :try_start_0
    new-instance v11, Ljava/io/ObjectOutputStream;

    invoke-direct {v11, v9}, Ljava/io/ObjectOutputStream;-><init>(Ljava/io/OutputStream;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_6

    if-lt v1, v4, :cond_d

    :try_start_1
    invoke-static {v2}, Llyiahf/vczjk/b06;->OooOOO(Landroid/net/NetworkRequest;)[I

    move-result-object v1

    const-string v12, "request.transportTypes"

    invoke-static {v1, v12}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    goto :goto_5

    :cond_d
    new-array v1, v12, [I

    fill-array-data v1, :array_0

    new-instance v13, Ljava/util/ArrayList;

    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    const/4 v14, 0x0

    :goto_4
    if-ge v14, v12, :cond_f

    aget v15, v1, v14

    invoke-static {v2, v15}, Llyiahf/vczjk/a32;->OooOo0(Landroid/net/NetworkRequest;I)Z

    move-result v16

    if-eqz v16, :cond_e

    invoke-static {v15}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v15

    invoke-virtual {v13, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_e
    add-int/2addr v14, v5

    goto :goto_4

    :cond_f
    invoke-static {v13}, Llyiahf/vczjk/d21;->o0000O0O(Ljava/util/List;)[I

    move-result-object v1

    :goto_5
    sget v12, Landroid/os/Build$VERSION;->SDK_INT:I

    if-lt v12, v4, :cond_10

    invoke-static {v2}, Llyiahf/vczjk/b06;->OooOOOO(Landroid/net/NetworkRequest;)[I

    move-result-object v2

    const-string v12, "request.capabilities"

    invoke-static {v2, v12}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    goto :goto_7

    :cond_10
    const/16 v12, 0x1d

    new-array v13, v12, [I

    fill-array-data v13, :array_1

    new-instance v14, Ljava/util/ArrayList;

    invoke-direct {v14}, Ljava/util/ArrayList;-><init>()V

    const/4 v15, 0x0

    :goto_6
    if-ge v15, v12, :cond_12

    aget v12, v13, v15

    invoke-static {v2, v12}, Llyiahf/vczjk/a32;->OooOoOO(Landroid/net/NetworkRequest;I)Z

    move-result v16

    if-eqz v16, :cond_11

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v12

    invoke-virtual {v14, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_11
    add-int/2addr v15, v5

    const/16 v12, 0x1d

    goto :goto_6

    :cond_12
    invoke-static {v14}, Llyiahf/vczjk/d21;->o0000O0O(Ljava/util/List;)[I

    move-result-object v2

    :goto_7
    array-length v12, v1

    invoke-virtual {v11, v12}, Ljava/io/ObjectOutputStream;->writeInt(I)V

    array-length v12, v1

    const/4 v13, 0x0

    :goto_8
    if-ge v13, v12, :cond_13

    aget v14, v1, v13

    invoke-virtual {v11, v14}, Ljava/io/ObjectOutputStream;->writeInt(I)V

    add-int/2addr v13, v5

    goto :goto_8

    :catchall_0
    move-exception v0

    move-object v1, v0

    goto/16 :goto_11

    :cond_13
    array-length v1, v2

    invoke-virtual {v11, v1}, Ljava/io/ObjectOutputStream;->writeInt(I)V

    array-length v1, v2

    const/4 v12, 0x0

    :goto_9
    if-ge v12, v1, :cond_14

    aget v13, v2, v12

    invoke-virtual {v11, v13}, Ljava/io/ObjectOutputStream;->writeInt(I)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    add-int/2addr v12, v5

    goto :goto_9

    :cond_14
    :try_start_2
    invoke-virtual {v11}, Ljava/io/ObjectOutputStream;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_6

    invoke-virtual {v9}, Ljava/io/ByteArrayOutputStream;->close()V

    invoke-virtual {v9}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    move-result-object v1

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    :goto_a
    const/16 v2, 0x19

    invoke-interface {v0, v2, v1}, Llyiahf/vczjk/ha9;->OoooO0(I[B)V

    iget-boolean v1, v7, Llyiahf/vczjk/qk1;->OooO0OO:Z

    int-to-long v1, v1

    const/16 v5, 0x1a

    invoke-interface {v0, v5, v1, v2}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget-boolean v1, v7, Llyiahf/vczjk/qk1;->OooO0Oo:Z

    int-to-long v1, v1

    const/16 v5, 0x1b

    invoke-interface {v0, v5, v1, v2}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget-boolean v1, v7, Llyiahf/vczjk/qk1;->OooO0o0:Z

    int-to-long v1, v1

    invoke-interface {v0, v8, v1, v2}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget-boolean v1, v7, Llyiahf/vczjk/qk1;->OooO0o:Z

    int-to-long v1, v1

    const/16 v12, 0x1d

    invoke-interface {v0, v12, v1, v2}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget-wide v1, v7, Llyiahf/vczjk/qk1;->OooO0oO:J

    invoke-interface {v0, v10, v1, v2}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget-wide v1, v7, Llyiahf/vczjk/qk1;->OooO0oo:J

    invoke-interface {v0, v4, v1, v2}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    const-string v1, "triggers"

    iget-object v2, v7, Llyiahf/vczjk/qk1;->OooO:Ljava/util/Set;

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v2}, Ljava/util/Set;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_15

    const/4 v9, 0x0

    new-array v1, v9, [B

    goto :goto_c

    :cond_15
    new-instance v1, Ljava/io/ByteArrayOutputStream;

    invoke-direct {v1}, Ljava/io/ByteArrayOutputStream;-><init>()V

    :try_start_3
    new-instance v4, Ljava/io/ObjectOutputStream;

    invoke-direct {v4, v1}, Ljava/io/ObjectOutputStream;-><init>(Ljava/io/OutputStream;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    :try_start_4
    invoke-interface {v2}, Ljava/util/Set;->size()I

    move-result v5

    invoke-virtual {v4, v5}, Ljava/io/ObjectOutputStream;->writeInt(I)V

    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_b
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_16

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/pk1;

    iget-object v7, v5, Llyiahf/vczjk/pk1;->OooO00o:Landroid/net/Uri;

    invoke-virtual {v7}, Landroid/net/Uri;->toString()Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v4, v7}, Ljava/io/ObjectOutputStream;->writeUTF(Ljava/lang/String;)V

    iget-boolean v5, v5, Llyiahf/vczjk/pk1;->OooO0O0:Z

    invoke-virtual {v4, v5}, Ljava/io/ObjectOutputStream;->writeBoolean(Z)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    goto :goto_b

    :catchall_1
    move-exception v0

    move-object v2, v0

    goto :goto_e

    :cond_16
    :try_start_5
    invoke-virtual {v4}, Ljava/io/ObjectOutputStream;->close()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    invoke-virtual {v1}, Ljava/io/ByteArrayOutputStream;->close()V

    invoke-virtual {v1}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    move-result-object v1

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    :goto_c
    const/16 v2, 0x20

    invoke-interface {v0, v2, v1}, Llyiahf/vczjk/ha9;->OoooO0(I[B)V

    return-void

    :goto_d
    move-object v2, v0

    goto :goto_f

    :goto_e
    :try_start_6
    throw v2
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    :catchall_2
    move-exception v0

    :try_start_7
    invoke-static {v4, v2}, Llyiahf/vczjk/rs;->OooOOO(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    throw v0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    :catchall_3
    move-exception v0

    goto :goto_d

    :goto_f
    :try_start_8
    throw v2
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_4

    :catchall_4
    move-exception v0

    invoke-static {v1, v2}, Llyiahf/vczjk/rs;->OooOOO(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    throw v0

    :goto_10
    move-object v1, v0

    goto :goto_12

    :goto_11
    :try_start_9
    throw v1
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_5

    :catchall_5
    move-exception v0

    :try_start_a
    invoke-static {v11, v1}, Llyiahf/vczjk/rs;->OooOOO(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    throw v0
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_6

    :catchall_6
    move-exception v0

    goto :goto_10

    :goto_12
    :try_start_b
    throw v1
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_7

    :catchall_7
    move-exception v0

    invoke-static {v9, v1}, Llyiahf/vczjk/rs;->OooOOO(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    throw v0

    :pswitch_1
    new-instance v0, Ljava/lang/ClassCastException;

    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    throw v0

    :pswitch_2
    move-object/from16 v0, p2

    check-cast v0, Llyiahf/vczjk/sqa;

    const/4 v0, 0x0

    throw v0

    :pswitch_3
    move-object/from16 v1, p2

    check-cast v1, Llyiahf/vczjk/kd9;

    iget-object v2, v1, Llyiahf/vczjk/kd9;->OooO00o:Ljava/lang/String;

    invoke-interface {v0, v5, v2}, Llyiahf/vczjk/ha9;->OooOOO0(ILjava/lang/String;)V

    iget v2, v1, Llyiahf/vczjk/kd9;->OooO0O0:I

    int-to-long v7, v2

    invoke-interface {v0, v4, v7, v8}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget v1, v1, Llyiahf/vczjk/kd9;->OooO0OO:I

    int-to-long v1, v1

    invoke-interface {v0, v3, v1, v2}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    return-void

    :pswitch_4
    move-object/from16 v7, p2

    check-cast v7, Llyiahf/vczjk/cx7;

    iget v8, v7, Llyiahf/vczjk/cx7;->OooO00o:I

    int-to-long v8, v8

    invoke-interface {v0, v5, v8, v9}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget-object v5, v7, Llyiahf/vczjk/cx7;->OooO0O0:Ljava/lang/String;

    if-nez v5, :cond_17

    invoke-interface {v0, v4}, Llyiahf/vczjk/ha9;->OooO0o0(I)V

    goto :goto_13

    :cond_17
    invoke-interface {v0, v4, v5}, Llyiahf/vczjk/ha9;->OooOOO0(ILjava/lang/String;)V

    :goto_13
    iget-object v4, v7, Llyiahf/vczjk/cx7;->OooO0OO:Ljava/lang/String;

    if-nez v4, :cond_18

    invoke-interface {v0, v3}, Llyiahf/vczjk/ha9;->OooO0o0(I)V

    goto :goto_14

    :cond_18
    invoke-interface {v0, v3, v4}, Llyiahf/vczjk/ha9;->OooOOO0(ILjava/lang/String;)V

    :goto_14
    iget v3, v7, Llyiahf/vczjk/cx7;->OooO0Oo:I

    int-to-long v3, v3

    invoke-interface {v0, v2, v3, v4}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget v2, v7, Llyiahf/vczjk/cx7;->OooO0o0:I

    int-to-long v2, v2

    invoke-interface {v0, v1, v2, v3}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget-boolean v1, v7, Llyiahf/vczjk/cx7;->OooO0o:Z

    int-to-long v1, v1

    invoke-interface {v0, v13, v1, v2}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    iget-object v1, v7, Llyiahf/vczjk/cx7;->OooO0oO:Ljava/lang/String;

    if-nez v1, :cond_19

    invoke-interface {v0, v15}, Llyiahf/vczjk/ha9;->OooO0o0(I)V

    goto :goto_15

    :cond_19
    invoke-interface {v0, v15, v1}, Llyiahf/vczjk/ha9;->OooOOO0(ILjava/lang/String;)V

    :goto_15
    return-void

    :pswitch_5
    move-object/from16 v1, p2

    check-cast v1, Llyiahf/vczjk/z17;

    iget-object v2, v1, Llyiahf/vczjk/z17;->OooO00o:Ljava/lang/String;

    invoke-interface {v0, v5, v2}, Llyiahf/vczjk/ha9;->OooOOO0(ILjava/lang/String;)V

    iget-object v1, v1, Llyiahf/vczjk/z17;->OooO0O0:Ljava/lang/Long;

    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    move-result-wide v1

    invoke-interface {v0, v4, v1, v2}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    return-void

    :pswitch_6
    move-object/from16 v1, p2

    check-cast v1, Llyiahf/vczjk/k62;

    iget-object v2, v1, Llyiahf/vczjk/k62;->OooO00o:Ljava/lang/String;

    invoke-interface {v0, v5, v2}, Llyiahf/vczjk/ha9;->OooOOO0(ILjava/lang/String;)V

    iget-object v1, v1, Llyiahf/vczjk/k62;->OooO0O0:Ljava/lang/String;

    invoke-interface {v0, v4, v1}, Llyiahf/vczjk/ha9;->OooOOO0(ILjava/lang/String;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    :array_0
    .array-data 4
        0x2
        0x0
        0x3
        0x6
        0x9
        0x8
        0x4
        0x1
        0x5
    .end array-data

    :array_1
    .array-data 4
        0x11
        0x5
        0x2
        0xa
        0x1d
        0x13
        0x3
        0x20
        0x7
        0x4
        0xc
        0x17
        0x0
        0x21
        0x14
        0xb
        0xd
        0x12
        0x15
        0xf
        0x23
        0x22
        0x8
        0x1
        0x19
        0xe
        0x10
        0x6
        0x9
    .end array-data
.end method

.method public final OooO0oo(Ljava/lang/Object;)V
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/yd7;->OooO00o()Llyiahf/vczjk/la9;

    move-result-object v0

    :try_start_0
    invoke-virtual {p0, v0, p1}, Llyiahf/vczjk/m62;->OooO0oO(Llyiahf/vczjk/la9;Ljava/lang/Object;)V

    invoke-interface {v0}, Llyiahf/vczjk/la9;->o00000O0()J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/yd7;->OooO0o(Llyiahf/vczjk/la9;)V

    return-void

    :catchall_0
    move-exception p1

    invoke-virtual {p0, v0}, Llyiahf/vczjk/yd7;->OooO0o(Llyiahf/vczjk/la9;)V

    throw p1
.end method
