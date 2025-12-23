.class public final Llyiahf/vczjk/jn6;
.super Llyiahf/vczjk/zo1;
.source "SourceFile"


# instance fields
.field I$0:I

.field I$1:I

.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field L$3:Ljava/lang/Object;

.field L$4:Ljava/lang/Object;

.field L$5:Ljava/lang/Object;

.field Z$0:Z

.field label:I

.field synthetic result:Ljava/lang/Object;

.field final synthetic this$0:Llyiahf/vczjk/kn6;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/kn6;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kn6;Llyiahf/vczjk/zo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/jn6;->this$0:Llyiahf/vczjk/kn6;

    invoke-direct {p0, p2}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    iput-object p1, p0, Llyiahf/vczjk/jn6;->result:Ljava/lang/Object;

    iget p1, p0, Llyiahf/vczjk/jn6;->label:I

    const/high16 v0, -0x80000000

    or-int/2addr p1, v0

    iput p1, p0, Llyiahf/vczjk/jn6;->label:I

    iget-object v0, p0, Llyiahf/vczjk/jn6;->this$0:Llyiahf/vczjk/kn6;

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    move-object v8, p0

    invoke-static/range {v0 .. v8}, Llyiahf/vczjk/kn6;->OooO00o(Llyiahf/vczjk/kn6;Ljava/util/List;IIZLlyiahf/vczjk/r25;Llyiahf/vczjk/r25;Llyiahf/vczjk/ni6;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
