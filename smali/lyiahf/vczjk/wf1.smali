.class public final Llyiahf/vczjk/wf1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $offsetChanges:Llyiahf/vczjk/ks0;

.field final synthetic $reader:Llyiahf/vczjk/is8;

.field final synthetic $to:Llyiahf/vczjk/wp5;

.field final synthetic this$0:Llyiahf/vczjk/zf1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zf1;Llyiahf/vczjk/ks0;Llyiahf/vczjk/is8;Llyiahf/vczjk/wp5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/wf1;->this$0:Llyiahf/vczjk/zf1;

    iput-object p2, p0, Llyiahf/vczjk/wf1;->$offsetChanges:Llyiahf/vczjk/ks0;

    iput-object p3, p0, Llyiahf/vczjk/wf1;->$reader:Llyiahf/vczjk/is8;

    iput-object p4, p0, Llyiahf/vczjk/wf1;->$to:Llyiahf/vczjk/wp5;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/wf1;->this$0:Llyiahf/vczjk/zf1;

    iget-object v1, v0, Llyiahf/vczjk/zf1;->Oooo0o0:Llyiahf/vczjk/sf1;

    iget-object v2, p0, Llyiahf/vczjk/wf1;->$offsetChanges:Llyiahf/vczjk/ks0;

    iget-object v3, p0, Llyiahf/vczjk/wf1;->$reader:Llyiahf/vczjk/is8;

    iget-object v4, p0, Llyiahf/vczjk/wf1;->$to:Llyiahf/vczjk/wp5;

    iget-object v5, v1, Llyiahf/vczjk/sf1;->OooO0O0:Llyiahf/vczjk/ks0;

    :try_start_0
    iput-object v2, v1, Llyiahf/vczjk/sf1;->OooO0O0:Llyiahf/vczjk/ks0;

    iget-object v2, v0, Llyiahf/vczjk/zf1;->Oooo000:Llyiahf/vczjk/is8;

    iget-object v6, v0, Llyiahf/vczjk/zf1;->OooOOO:[I

    iget-object v7, v0, Llyiahf/vczjk/zf1;->OooOo0:Llyiahf/vczjk/or5;

    const/4 v8, 0x0

    iput-object v8, v0, Llyiahf/vczjk/zf1;->OooOOO:[I

    iput-object v8, v0, Llyiahf/vczjk/zf1;->OooOo0:Llyiahf/vczjk/or5;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    :try_start_1
    iput-object v3, v0, Llyiahf/vczjk/zf1;->Oooo000:Llyiahf/vczjk/is8;

    iget-boolean v3, v1, Llyiahf/vczjk/sf1;->OooO0o0:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    const/4 v8, 0x0

    :try_start_2
    iput-boolean v8, v1, Llyiahf/vczjk/sf1;->OooO0o0:Z

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v4, 0x0

    const/4 v8, 0x0

    invoke-static {v0, v4, v8}, Llyiahf/vczjk/zf1;->OooO0O0(Llyiahf/vczjk/zf1;Llyiahf/vczjk/ps6;Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    :try_start_3
    iput-boolean v3, v1, Llyiahf/vczjk/sf1;->OooO0o0:Z
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    :try_start_4
    iput-object v2, v0, Llyiahf/vczjk/zf1;->Oooo000:Llyiahf/vczjk/is8;

    iput-object v6, v0, Llyiahf/vczjk/zf1;->OooOOO:[I

    iput-object v7, v0, Llyiahf/vczjk/zf1;->OooOo0:Llyiahf/vczjk/or5;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    iput-object v5, v1, Llyiahf/vczjk/sf1;->OooO0O0:Llyiahf/vczjk/ks0;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :catchall_0
    move-exception v4

    :try_start_5
    iput-boolean v3, v1, Llyiahf/vczjk/sf1;->OooO0o0:Z

    throw v4
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    :catchall_1
    move-exception v3

    :try_start_6
    iput-object v2, v0, Llyiahf/vczjk/zf1;->Oooo000:Llyiahf/vczjk/is8;

    iput-object v6, v0, Llyiahf/vczjk/zf1;->OooOOO:[I

    iput-object v7, v0, Llyiahf/vczjk/zf1;->OooOo0:Llyiahf/vczjk/or5;

    throw v3
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    :catchall_2
    move-exception v0

    iput-object v5, v1, Llyiahf/vczjk/sf1;->OooO0O0:Llyiahf/vczjk/ks0;

    throw v0
.end method
