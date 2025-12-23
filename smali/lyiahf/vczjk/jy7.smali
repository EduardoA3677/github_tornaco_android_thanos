.class public final Llyiahf/vczjk/jy7;
.super Llyiahf/vczjk/zo1;
.source "SourceFile"


# instance fields
.field L$0:Ljava/lang/Object;

.field label:I

.field synthetic result:Ljava/lang/Object;

.field final synthetic this$0:Llyiahf/vczjk/ny7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ny7;Llyiahf/vczjk/zo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/jy7;->this$0:Llyiahf/vczjk/ny7;

    invoke-direct {p0, p2}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iput-object p1, p0, Llyiahf/vczjk/jy7;->result:Ljava/lang/Object;

    iget p1, p0, Llyiahf/vczjk/jy7;->label:I

    const/high16 v0, -0x80000000

    or-int/2addr p1, v0

    iput p1, p0, Llyiahf/vczjk/jy7;->label:I

    iget-object p1, p0, Llyiahf/vczjk/jy7;->this$0:Llyiahf/vczjk/ny7;

    const/4 v0, 0x0

    invoke-virtual {p1, v0, p0}, Llyiahf/vczjk/ny7;->OooO0oo(Ltornaco/apps/thanox/running/RunningAppState;Llyiahf/vczjk/zo1;)V

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1
.end method
