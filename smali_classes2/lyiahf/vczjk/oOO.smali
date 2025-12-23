.class public final synthetic Llyiahf/vczjk/oOO;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic OooOOO:Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

.field public final synthetic OooOOO0:Llyiahf/vczjk/a;

.field public final synthetic OooOOOO:Ljava/lang/String;

.field public final synthetic OooOOOo:Ljava/lang/String;

.field public final synthetic OooOOo:I

.field public final synthetic OooOOo0:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/a;Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/oOO;->OooOOO0:Llyiahf/vczjk/a;

    iput-object p2, p0, Llyiahf/vczjk/oOO;->OooOOO:Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    iput-object p3, p0, Llyiahf/vczjk/oOO;->OooOOOO:Ljava/lang/String;

    iput-object p4, p0, Llyiahf/vczjk/oOO;->OooOOOo:Ljava/lang/String;

    iput-object p5, p0, Llyiahf/vczjk/oOO;->OooOOo0:Ljava/lang/String;

    iput p6, p0, Llyiahf/vczjk/oOO;->OooOOo:I

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/oOO;->OooOOO0:Llyiahf/vczjk/a;

    iget-object v1, v0, Llyiahf/vczjk/a;->OooOO0:Llyiahf/vczjk/x19;

    invoke-static {}, Lgithub/tornaco/android/thanos/core/app/start/StartRecord;->builder()Lgithub/tornaco/android/thanos/core/app/start/StartRecord$StartRecordBuilder;

    move-result-object v2

    iget-object v3, p0, Llyiahf/vczjk/oOO;->OooOOO:Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;->getPackageName()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v2, v4}, Lgithub/tornaco/android/thanos/core/app/start/StartRecord$StartRecordBuilder;->packageName(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/app/start/StartRecord$StartRecordBuilder;

    move-result-object v2

    iget-object v0, v0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOO0O:Llyiahf/vczjk/uv6;

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;->getPackageName()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v0, v4}, Llyiahf/vczjk/uv6;->OooOooO(Ljava/lang/String;)I

    move-result v0

    invoke-virtual {v2, v0}, Lgithub/tornaco/android/thanos/core/app/start/StartRecord$StartRecordBuilder;->appFlags(I)Lgithub/tornaco/android/thanos/core/app/start/StartRecord$StartRecordBuilder;

    move-result-object v0

    sget-object v2, Llyiahf/vczjk/l77;->OooO00o:Ljava/util/Set;

    iget-object v2, p0, Llyiahf/vczjk/oOO;->OooOOOO:Ljava/lang/String;

    invoke-static {v2}, Llyiahf/vczjk/l77;->OooO00o(Ljava/lang/String;)I

    move-result v4

    invoke-virtual {v0, v4}, Lgithub/tornaco/android/thanos/core/app/start/StartRecord$StartRecordBuilder;->method(I)Lgithub/tornaco/android/thanos/core/app/start/StartRecord$StartRecordBuilder;

    move-result-object v0

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v5, p0, Llyiahf/vczjk/oOO;->OooOOOo:Ljava/lang/String;

    const-string v6, "/"

    invoke-static {v4, v5, v6, v2, v6}, Llyiahf/vczjk/q99;->OooOO0(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    iget-object v2, p0, Llyiahf/vczjk/oOO;->OooOOo0:Ljava/lang/String;

    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2}, Lgithub/tornaco/android/thanos/core/app/start/StartRecord$StartRecordBuilder;->requestPayload(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/app/start/StartRecord$StartRecordBuilder;

    move-result-object v0

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;->getStartResult()Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    move-result-object v2

    invoke-virtual {v0, v2}, Lgithub/tornaco/android/thanos/core/app/start/StartRecord$StartRecordBuilder;->result(Lgithub/tornaco/android/thanos/core/app/start/StartResult;)Lgithub/tornaco/android/thanos/core/app/start/StartRecord$StartRecordBuilder;

    move-result-object v0

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v2

    invoke-virtual {v0, v2, v3}, Lgithub/tornaco/android/thanos/core/app/start/StartRecord$StartRecordBuilder;->whenByMills(J)Lgithub/tornaco/android/thanos/core/app/start/StartRecord$StartRecordBuilder;

    move-result-object v0

    const-string v2, "checkStartProcess"

    invoke-virtual {v0, v2}, Lgithub/tornaco/android/thanos/core/app/start/StartRecord$StartRecordBuilder;->checker(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/app/start/StartRecord$StartRecordBuilder;

    move-result-object v0

    iget v2, p0, Llyiahf/vczjk/oOO;->OooOOo:I

    invoke-virtual {v0, v2}, Lgithub/tornaco/android/thanos/core/app/start/StartRecord$StartRecordBuilder;->userId(I)Lgithub/tornaco/android/thanos/core/app/start/StartRecord$StartRecordBuilder;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/start/StartRecord$StartRecordBuilder;->build()Lgithub/tornaco/android/thanos/core/app/start/StartRecord;

    move-result-object v0

    invoke-virtual {v1, v0}, Llyiahf/vczjk/x19;->OooO00o(Lgithub/tornaco/android/thanos/core/app/start/StartRecord;)V

    return-void
.end method
